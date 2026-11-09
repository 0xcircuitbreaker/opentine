"""The published JSON Schemas: lookup, detection and validation (0.45).

Definitions live in :mod:`opentine._schema_defs` (object kinds) and
:mod:`opentine._schema_defs_cli` (``--json`` outputs) and
:mod:`opentine._schema_defs_redact` (redaction and doctor) and
:mod:`opentine._schema_defs_share` (tombstones, redacted copies) and
:mod:`opentine._schema_defs_ci` (CI gate and server trust policies) and
:mod:`opentine._schema_defs_hook` (``opentine-hook/1``) and
:mod:`opentine._schema_defs_merge` (merges, 0.47) and
:mod:`opentine._schema_defs_review` (Reviews, 0.47) and
:mod:`opentine._schema_defs_registry` (prompts, memory, ``eval ci``) and
:mod:`opentine._schema_defs_extend` (plugins, experts); ``docs/schemas`` is
their rendered copy (``scripts/gen_schemas.py``). A schema's *name* is its file
stem, e.g. ``tine-verify-report-2``; the tag a document carries
(``tine-verify-report/2``) maps to it by spelling ``/`` as ``-``.
"""

from __future__ import annotations

import json
from typing import Any

from opentine import _jsonschema
from opentine._schema_defs import SCHEMAS as _OBJECTS
from opentine._schema_defs_ci import KIND_SCHEMAS as _CI_KINDS
from opentine._schema_defs_ci import SCHEMAS as _CI
from opentine._schema_defs_cli import COMMAND_SCHEMAS as _CLI_COMMANDS
from opentine._schema_defs_cli import SCHEMAS as _CLI
from opentine._schema_defs_events import SCHEMAS as _EVENTS
from opentine._schema_defs_extend import COMMAND_SCHEMAS as _EXTEND_COMMANDS
from opentine._schema_defs_extend import SCHEMAS as _EXTEND
from opentine._schema_defs_hook import COMMAND_SCHEMAS as _HOOK_COMMANDS
from opentine._schema_defs_hook import SCHEMAS as _HOOK
from opentine._schema_defs_hosted import COMMAND_SCHEMAS as _HOSTED_COMMANDS
from opentine._schema_defs_hosted import SCHEMAS as _HOSTED
from opentine._schema_defs_merge import COMMAND_SCHEMAS as _MERGE_COMMANDS
from opentine._schema_defs_merge import KIND_SCHEMAS as _MERGE_KINDS
from opentine._schema_defs_merge import SCHEMAS as _MERGE
from opentine._schema_defs_project import COMMAND_SCHEMAS as _PROJECT_COMMANDS
from opentine._schema_defs_project import KIND_SCHEMAS as _PROJECT_KINDS
from opentine._schema_defs_project import SCHEMAS as _PROJECT
from opentine._schema_defs_redact import COMMAND_SCHEMAS as _REDACT_COMMANDS
from opentine._schema_defs_redact import KIND_SCHEMAS as _REDACT_KINDS
from opentine._schema_defs_redact import KIND_VERSION_SCHEMAS
from opentine._schema_defs_redact import SCHEMAS as _REDACT
from opentine._schema_defs_registry import COMMAND_SCHEMAS as _REGISTRY_COMMANDS
from opentine._schema_defs_registry import KIND_SCHEMAS as _REGISTRY_KINDS
from opentine._schema_defs_registry import SCHEMAS as _REGISTRY
from opentine._schema_defs_review import COMMAND_SCHEMAS as _REVIEW_COMMANDS
from opentine._schema_defs_review import KIND_SCHEMAS as _REVIEW_KINDS
from opentine._schema_defs_review import SCHEMAS as _REVIEW
from opentine._schema_defs_share import COMMAND_SCHEMAS as _SHARE_COMMANDS
from opentine._schema_defs_share import KIND_SCHEMAS as _SHARE_KINDS
from opentine._schema_defs_share import SCHEMAS as _SHARE

SCHEMAS: dict[str, dict[str, Any]] = {
    **_OBJECTS,
    **_CLI,
    **_EVENTS,
    **_REDACT,
    **_HOSTED,
    **_SHARE,
    **_CI,
    **_HOOK,
    **_PROJECT,
    **_MERGE,
    **_REVIEW,
    **_REGISTRY,
    **_EXTEND,
}
COMMAND_SCHEMAS: dict[str, str] = {
    **_CLI_COMMANDS,
    **_REDACT_COMMANDS,
    **_HOSTED_COMMANDS,
    **_SHARE_COMMANDS,
    **_HOOK_COMMANDS,
    **_PROJECT_COMMANDS,
    **_MERGE_COMMANDS,
    **_REVIEW_COMMANDS,
    **_REGISTRY_COMMANDS,
    **_EXTEND_COMMANDS,
}
KIND_SCHEMAS: dict[str, str] = {
    **_REDACT_KINDS,
    **_SHARE_KINDS,
    **_CI_KINDS,
    **_PROJECT_KINDS,
    **_MERGE_KINDS,
    **_REVIEW_KINDS,
    **_REGISTRY_KINDS,
}
ENVELOPE = "tine-cli-envelope-1"
#: Keys a document names its own format with, in the order they are tried.
TAG_KEYS = ("schema", "scheme", "format", "protocol")


class SchemaError(LookupError):
    """No such schema, or no schema can be chosen for a document."""


def render(schema: dict[str, Any]) -> str:
    """The published bytes of *schema* (what ``docs/schemas`` holds)."""
    return json.dumps(schema, indent=2, ensure_ascii=False) + "\n"


def names() -> list[str]:
    return sorted(SCHEMAS)


def stem(name: str) -> str:
    """``tine-verify-report/2``, ``…-2.schema.json`` or a URL -> ``tine-verify-report-2``."""
    name = name.rsplit("/", 1)[-1] if name.endswith(".json") else name
    return name.removesuffix(".json").removesuffix(".schema").replace("/", "-")


def get(name: str) -> dict[str, Any]:
    key = stem(name)
    if key not in SCHEMAS:
        raise SchemaError(f"no published schema {name!r} (see `tine schema list`)")
    return SCHEMAS[key]


def detect(document: Any) -> str:
    """The schema name *document* declares, by its tag or its ``command``."""
    if isinstance(document, dict):
        tagged = False
        for key in TAG_KEYS:
            tag = document.get(key)
            if isinstance(tag, str) and stem(tag) in SCHEMAS:
                return stem(tag)
            tagged = tagged or isinstance(tag, str) and "/" in tag
        command = document.get("command")
        kind = document.get("kind")
        if command is None and isinstance(kind, str) and kind in KIND_SCHEMAS:
            versioned = (kind, document.get("report_version"))
            return KIND_VERSION_SCHEMAS.get(versioned, KIND_SCHEMAS[kind])  # type: ignore[arg-type]
        if tagged and isinstance(command, str):
            # It names a format of its own that is not published (yet): hold it
            # to the envelope, not to the schema of another shape of `command`.
            return ENVELOPE
        if isinstance(command, str):
            return COMMAND_SCHEMAS.get(command, ENVELOPE)
        if "error" in document:
            return ENVELOPE
    raise SchemaError("cannot tell which schema this document follows; name one")


def validate(document: Any, name: str | None = None) -> tuple[str, list[str]]:
    """``(schema name, errors)``; an empty error list means *document* is valid."""
    key = stem(name) if name else detect(document)
    return key, _jsonschema.validate(get(key), document, get)


def validate_output(document: Any) -> list[str]:
    """A ``--json`` output against the envelope and, when published, its own schema."""
    errors = _jsonschema.validate(SCHEMAS[ENVELOPE], document, get)
    key = detect(document)
    if key != ENVELOPE:
        errors += [f"[{key}] {e}" for e in _jsonschema.validate(get(key), document, get)]
    return errors


def summary(name: str) -> str:
    schema = SCHEMAS[name]
    return str(schema.get("title") or name)


__all__ = [
    "COMMAND_SCHEMAS",
    "ENVELOPE",
    "SCHEMAS",
    "SchemaError",
    "detect",
    "get",
    "names",
    "render",
    "stem",
    "summary",
    "validate",
    "validate_output",
]
