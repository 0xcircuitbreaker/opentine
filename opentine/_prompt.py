"""``opentine.prompt``: a signed, hash-chained prompt version (0.47, SPEC 4.19).

The prompt registry (``tine prompt push|label|get``) stores each version of a
named prompt template as one record: its ``name``, a ``version`` counting from
1, ``prev`` (the blob oid of the previous version's canonical bytes, ``null``
for version 1), the ``template`` text, the ``variables`` it names (exactly the
sorted, distinct ``{{name}}`` placeholders of the template), the ``model`` it
was written for (or ``null``) and ``created_at``.

A version is signed (``tine-sig/3``, Ed25519 only) over ``opentine.prompt.v1:``
+ JCS of ``{body, header}``; the next version of a chain is signed by the same
key as its predecessor. Labels (``production``, ``staging``) are refs naming a
version, not part of it: moving a label never changes what a run or an eval
verdict that names the version's digest pointed at. :func:`check` is the
reference for the ``prompt.verify`` conformance op (``vectors/68-prompt.json``).
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

from opentine._signed_record import BLOB_OID, NAME, WHEN, RecordError, check_signature, fields
from opentine._signed_record import sign as _sign
from opentine.kernel import ObjectEnvelope, canonical_json

KIND = "opentine.prompt"
DOMAIN = b"opentine.prompt.v1:"
CODE = "prompt"
SUBJECT = "prompt version"
FIELDS = (
    "kind",
    "prompt_version",
    "name",
    "version",
    "prev",
    "template",
    "variables",
    "model",
    "created_at",
)
MAX_TEMPLATE_BYTES = 65_536
MAX_VERSION = 2**31 - 1
PROMPT_NAME = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
LABEL = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
PLACEHOLDER = re.compile(r"\{\{([A-Za-z_][A-Za-z0-9_]{0,63})\}\}")


def _malformed(message: str) -> RecordError:
    return RecordError("prompt.malformed", f"prompt version is malformed: {message}")


def digest(record: dict[str, Any]) -> str:
    """The blob oid of *record*'s canonical bytes: what the next version's ``prev`` names."""
    return ObjectEnvelope.create("blob", canonical_json(record)).oid


def placeholders(template: str) -> list[str]:
    """The sorted, distinct ``{{name}}`` placeholders of *template*."""
    return sorted(set(PLACEHOLDER.findall(template)))


def body(record: Any) -> dict[str, Any]:
    """The signed body of *record*, after the field rules."""
    out = fields(record, KIND, FIELDS, CODE, SUBJECT)
    if isinstance(out["prompt_version"], bool) or out["prompt_version"] != 1:
        raise _malformed("prompt_version must be 1")
    if not isinstance(out["name"], str) or not PROMPT_NAME.fullmatch(out["name"]):
        raise _malformed("name is 1 to 64 of a-z 0-9 . _ - starting with a letter or digit")
    version = out["version"]
    if isinstance(version, bool) or not isinstance(version, int) or not 1 <= version <= MAX_VERSION:
        raise _malformed("version counts from 1")
    prev = out["prev"]
    if (version == 1) != (prev is None) or (
        prev is not None and not (isinstance(prev, str) and BLOB_OID.fullmatch(prev))
    ):
        raise _malformed("prev is null for version 1 and a blob oid after it")
    template = out["template"]
    if (
        not isinstance(template, str)
        or not template
        or "\0" in template
        or len(template.encode("utf-8", "surrogatepass")) > MAX_TEMPLATE_BYTES
    ):
        raise _malformed("template is 1 to 65536 bytes of text without NUL")
    variables = out["variables"]
    if not isinstance(variables, list) or not all(isinstance(v, str) for v in variables):
        raise _malformed("variables is a list of names")
    model = out["model"]
    if model is not None and not (isinstance(model, str) and NAME.fullmatch(model)):
        raise _malformed("model is a name or null")
    if not isinstance(out["created_at"], str) or not WHEN.fullmatch(out["created_at"]):
        raise _malformed("created_at must be an RFC 3339 UTC time (YYYY-MM-DDTHH:MM:SSZ)")
    if variables != placeholders(template):
        raise RecordError(
            "prompt.variables-mismatch",
            "the variables are not the template's sorted, distinct placeholders",
        )
    return out


def build(
    name: str,
    template: str,
    *,
    previous: dict[str, Any] | None = None,
    model: str | None = None,
    created_at: str | None = None,
) -> dict[str, Any]:
    """An unsigned version; with *previous*, the next version of its chain."""
    record = {
        "kind": KIND,
        "prompt_version": 1,
        "name": name,
        "version": 1 if previous is None else previous["version"] + 1,
        "prev": None if previous is None else digest(previous),
        "template": template,
        "variables": placeholders(template),
        "model": model,
        "created_at": created_at or datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    return body(record)


def sign(record: dict[str, Any], key: Any, **header: Any) -> dict[str, Any]:
    return _sign(body(record), DOMAIN, SUBJECT, key, algorithm="ed25519", **header)


def _signer(record: dict[str, Any], found: dict[str, Any], public_key: bytes | None) -> tuple:
    block = record.get("signature")
    if isinstance(block, dict) and block.get("alg") not in (None, "ed25519"):
        raise RecordError("prompt.wrong-key", "a prompt version is signed with an Ed25519 key")
    state = check_signature(
        record, found, domain=DOMAIN, code=CODE, subject=SUBJECT, public_key=public_key
    )
    return str(block["public_key"]), state  # type: ignore[index]


def check(
    record: Any, *, previous: Any = None, public_key: bytes | None = None
) -> dict[str, Any]:
    """``{name, version, digest, signer, variables, state}``; :class:`RecordError` else.

    With *previous* the version must follow it (``prev``, ``version`` and
    ``name``) and be signed by the same key (``prompt.wrong-signer``).
    """
    found = body(record)
    signer, state = _signer(record, found, public_key)
    if previous is not None:
        prior = body(previous)
        if (
            found["prev"] != digest(previous)
            or found["version"] != prior["version"] + 1
            or found["name"] != prior["name"]
        ):
            raise RecordError(
                "prompt.chain-break",
                f"version {found['version']} does not follow its predecessor",
            )
        block = previous.get("signature")
        if not isinstance(block, dict) or block.get("public_key") != signer:
            raise RecordError(
                "prompt.wrong-signer", "a prompt version is signed by its predecessor's key"
            )
    return {
        "name": found["name"],
        "version": found["version"],
        "digest": digest(record),
        "signer": signer,
        "variables": list(found["variables"]),
        "state": state,
    }


def render(record: dict[str, Any], values: dict[str, str]) -> str:
    """The template with every placeholder replaced; a missing value is refused."""
    missing = [name for name in record["variables"] if name not in values]
    if missing:
        raise ValueError(f"no value for prompt variable {missing[0]}")
    return PLACEHOLDER.sub(lambda match: str(values[match.group(1)]), record["template"])


__all__ = [
    "DOMAIN",
    "FIELDS",
    "KIND",
    "LABEL",
    "PROMPT_NAME",
    "body",
    "build",
    "check",
    "digest",
    "placeholders",
    "render",
    "sign",
]
