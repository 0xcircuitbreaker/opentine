"""Prompt versions and memory notes with the standard library (0.47, SPEC 4.19-4.20).

An independent port, for ``tine-verify.pyz``, of ``opentine._prompt.check``
(a signed, hash-chained ``opentine.prompt`` version) and
``opentine._memory.check`` (a signed ``opentine.memory`` note). Signatures are
``tine-sig/3`` Ed25519 blocks over each kind's domain + JCS of ``{"body",
"header"}``. ``tine-verify.pyz FILE`` takes one record, or a prompt history
(a list, oldest first, or ``{"versions": [...]}``).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from ._artifact import check as row
from ._gitobj import Refused
from ._project import _signed, digest

PROMPT = "opentine.prompt"
MEMORY = "opentine.memory"
_PROMPT_FIELDS = ("kind", "prompt_version", "name", "version", "prev", "template", "variables",
                  "model", "created_at")  # fmt: skip
_MEMORY_FIELDS = ("kind", "memory_version", "scope", "topic", "text", "tags", "subject",
                  "supersedes", "author", "created_at")  # fmt: skip
_ID = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
_TAG = re.compile(r"[a-z0-9][a-z0-9._:-]{0,63}")
_NAME = re.compile(r"[A-Za-z0-9_.:/@+-]{1,256}")
_WHEN = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
_BLOB = re.compile(r"blob:sha256:[0-9a-f]{64}")
_RUN = re.compile(r"run:sha256:[0-9a-f]{64}")
_HOLE = re.compile(r"\{\{([A-Za-z_][A-Za-z0-9_]{0,63})\}\}")
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
_BLANK = re.compile(r"[ \t\n]*")


def _is(value: Any, pattern: re.Pattern) -> bool:
    return isinstance(value, str) and bool(pattern.fullmatch(value))


def _int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _body(record: Any, kind: str, names: tuple, code: str, subject: str) -> dict:
    if not isinstance(record, dict) or record.get("kind") != kind:
        raise Refused(f"{code}.malformed", f"{subject} is malformed: kind is not {kind}")
    if set(record) - {*names, "signature"} or set(names) - set(record):
        raise Refused(f"{code}.malformed", f"{subject} is malformed: wrong set of fields")
    return {name: record[name] for name in names}


def _bytes(text: str) -> int:
    return len(text.encode("utf-8", "surrogatepass"))


def _prompt_body(record: Any) -> dict:
    body = _body(record, PROMPT, _PROMPT_FIELDS, "prompt", "prompt version")
    version, prev, template = body["version"], body["prev"], body["template"]
    checks = (
        (_int(body["prompt_version"]) and body["prompt_version"] == 1, "prompt_version"),
        (_is(body["name"], _ID), "name"),
        (_int(version) and 1 <= version <= 2**31 - 1, "version counts from 1"),
        ((version == 1) == (prev is None) and (prev is None or _is(prev, _BLOB)), "prev"),
        (isinstance(template, str) and template != "" and "\0" not in template
         and _bytes(template) <= 65_536, "template"),
        (isinstance(body["variables"], list)
         and all(isinstance(v, str) for v in body["variables"]), "variables"),
        (body["model"] is None or _is(body["model"], _NAME), "model"),
        (_is(body["created_at"], _WHEN), "created_at must be an RFC 3339 UTC time"),
    )  # fmt: skip
    for ok, message in checks:
        if not ok:
            raise Refused("prompt.malformed", f"prompt version is malformed: {message}")
    if body["variables"] != sorted(set(_HOLE.findall(template))):
        raise Refused("prompt.variables-mismatch", "the variables are not the placeholders")
    return body


def prompt_verify(record: Any, previous: Any = None, public_key: bytes | None = None) -> dict:
    """SPEC 4.19: ``{name, version, digest, signer, variables, state}``; :class:`Refused` else."""
    body = _prompt_body(record)
    signer = _signed(record, body, b"opentine.prompt.v1:", "prompt", "prompt version", public_key)
    if previous is not None:
        prior = _prompt_body(previous)
        if (
            body["prev"] != digest(previous)
            or body["version"] != prior["version"] + 1
            or body["name"] != prior["name"]
        ):
            raise Refused("prompt.chain-break", "the version does not follow its predecessor")
        block = previous.get("signature")
        if not isinstance(block, dict) or block.get("public_key") != signer:
            raise Refused("prompt.wrong-signer", "not signed by its predecessor's key")
    return {"name": body["name"], "version": body["version"], "digest": digest(record),
            "signer": signer, "variables": list(body["variables"]),
            "state": "verified" if public_key is not None else "verified-tofu"}  # fmt: skip


def prompt_chain(versions: Any, public_key: bytes | None = None) -> dict:
    if not isinstance(versions, list) or not 1 <= len(versions) <= 10_000:
        raise Refused("prompt.malformed", "prompt version is malformed: not a history")
    last = prompt_verify(versions[0], None, public_key)
    if last["version"] != 1:
        raise Refused("prompt.chain-break", "a history starts at version 1")
    for previous, record in zip(versions, versions[1:]):
        last = prompt_verify(record, previous, None)
    return {**last, "versions": len(versions)}


def memory_verify(record: Any, public_key: bytes | None = None, team: Any = ()) -> dict:
    """SPEC 4.20: ``{scope, topic, digest, signer, subject, supersedes, tags, state}``."""
    body = _body(record, MEMORY, _MEMORY_FIELDS, "memory", "memory note")
    text, tags, subject = body["text"], body["tags"], body["subject"]
    checks = (
        (_int(body["memory_version"]) and body["memory_version"] == 1, "memory_version"),
        (_is(body["scope"], _ID) and _is(body["topic"], _ID), "scope and topic"),
        (isinstance(text, str) and not _BLANK.fullmatch(text) and _bytes(text) <= 8192
         and not _CONTROL.search(text), "text"),
        (isinstance(tags, list) and len(tags) <= 32 and all(_is(t, _TAG) for t in tags)
         and tags == sorted(set(tags)), "tags"),
        (subject is None or _is(subject, _RUN) or _is(subject, _BLOB), "subject"),
        (body["supersedes"] is None or _is(body["supersedes"], _BLOB), "supersedes"),
        (_is(body["author"], _NAME), "author"),
        (_is(body["created_at"], _WHEN), "created_at must be an RFC 3339 UTC time"),
    )  # fmt: skip
    for ok, message in checks:
        if not ok:
            raise Refused("memory.malformed", f"memory note is malformed: {message}")
    signer = _signed(record, body, b"opentine.memory.v1:", "memory", "memory note", public_key)
    members = set(team or ())
    if members and signer not in members:
        raise Refused("memory.untrusted-signer", "the memory note's signer is not on the team")
    state = "verified" if public_key is not None or members else "verified-tofu"
    return {"scope": body["scope"], "topic": body["topic"], "digest": digest(record),
            "signer": signer, "subject": subject, "supersedes": body["supersedes"],
            "tags": list(tags), "state": state}  # fmt: skip


def _load(path: Path) -> Any:
    value = json.loads(path.read_text("utf-8"))
    if isinstance(value, dict) and isinstance(value.get("versions"), list):
        return value["versions"]
    return value


def kind(path: Path) -> str | None:
    """``prompt`` or ``memory`` when *path* holds one; ``None`` else."""
    if path.suffix != ".json" or not path.is_file() or path.stat().st_size > 16 << 20:
        return None
    try:
        value = _load(path)
    except (OSError, ValueError, RecursionError):
        return None
    first = value[0] if isinstance(value, list) and value else value
    found = first.get("kind") if isinstance(first, dict) else None
    return {PROMPT: "prompt", MEMORY: "memory"}.get(found) if isinstance(found, str) else None


def verify(path: Path, public_key: bytes | None) -> list[dict[str, Any]]:
    """One check for the prompt version, prompt history or memory note at *path*."""
    mode, value = kind(path), _load(path)
    try:
        if mode == "memory":
            found = memory_verify(value, public_key)
        elif isinstance(value, list):
            found = prompt_chain(value, public_key)
        else:
            found = prompt_verify(value, None, public_key)
    except Refused as exc:
        return [row(str(mode), "fail", exc.code, str(exc))]
    return [row(str(mode), "pass", f"{mode}.verified", PROMPT if mode == "prompt" else MEMORY,
                **found)]  # fmt: skip


__all__ = ["kind", "memory_verify", "prompt_chain", "prompt_verify", "verify"]
