"""The published JSON Schemas: lookup, detection and validation (0.45).

Definitions live in :mod:`opentine._schema_defs` (object kinds) and
:mod:`opentine._schema_defs_cli` (``--json`` outputs); ``docs/schemas`` is
their rendered copy (``scripts/gen_schemas.py``). A schema's *name* is its file
stem, e.g. ``tine-verify-report-2``; the tag a document carries
(``tine-verify-report/2``) maps to it by spelling ``/`` as ``-``.
"""

from __future__ import annotations

import json
from typing import Any

from opentine import _jsonschema
from opentine._schema_defs import SCHEMAS as _OBJECTS
from opentine._schema_defs_cli import COMMAND_SCHEMAS
from opentine._schema_defs_cli import SCHEMAS as _CLI
from opentine._schema_defs_events import SCHEMAS as _EVENTS

SCHEMAS: dict[str, dict[str, Any]] = {**_OBJECTS, **_CLI, **_EVENTS}
ENVELOPE = "tine-cli-envelope-1"
#: Keys a document names its own format with, in the order they are tried.
TAG_KEYS = ("schema", "scheme", "format")


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
