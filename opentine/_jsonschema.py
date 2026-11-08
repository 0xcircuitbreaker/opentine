"""A small JSON Schema 2020-12 validator for the schemas OpenTine publishes (0.45).

OpenTine's core takes no ``jsonschema`` dependency, and its published schemas
(``opentine/data/schemas``, mirrored in ``docs/schemas``) use only the subset
below, so this module validates them exactly. A schema that uses a keyword
outside the subset is refused by :func:`check_schema` rather than silently
under-checked:

``$schema`` ``$id`` ``$ref`` ``$defs`` ``$comment`` ``title`` ``description``
``type`` ``enum`` ``const`` ``properties`` ``required`` ``additionalProperties``
``patternProperties`` ``items`` ``prefixItems`` ``minItems`` ``maxItems``
``minimum`` ``maximum`` ``minLength`` ``maxLength`` ``pattern`` ``format``
(annotation only) ``anyOf`` ``oneOf`` ``allOf`` ``not`` ``examples``
``default`` ``deprecated``.

``$ref`` resolves ``#/$defs/NAME`` inside a document and ``NAME.schema.json``
(optionally followed by ``#/$defs/...``) against the other published schemas.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

KEYWORDS = frozenset(
    "$schema $id $ref $defs $comment title description type enum const properties required "
    "additionalProperties patternProperties items prefixItems minItems maxItems minimum maximum "
    "minLength maxLength pattern format anyOf oneOf allOf not examples default deprecated".split()
)
_TYPES: dict[str, Callable[[Any], bool]] = {
    "object": lambda v: isinstance(v, dict),
    "array": lambda v: isinstance(v, list),
    "string": lambda v: isinstance(v, str),
    "boolean": lambda v: isinstance(v, bool),
    "null": lambda v: v is None,
    "integer": lambda v: (
        isinstance(v, int) and not isinstance(v, bool) or isinstance(v, float) and v.is_integer()
    ),
    "number": lambda v: isinstance(v, int | float) and not isinstance(v, bool),
}
_SUBSCHEMA_MAPS = ("properties", "patternProperties", "$defs")
_SUBSCHEMA_LISTS = ("anyOf", "oneOf", "allOf", "prefixItems")
_SUBSCHEMA_ONE = ("additionalProperties", "items", "not")

Resolver = Callable[[str], dict[str, Any]]


def check_schema(schema: Any, where: str = "#") -> list[str]:
    """Problems that make *schema* unusable here: unknown keywords, bad shapes."""
    if isinstance(schema, bool):
        return []
    if not isinstance(schema, dict):
        return [f"{where}: a schema is an object or a boolean"]
    errors = [f"{where}: unsupported keyword {k!r}" for k in schema if k not in KEYWORDS]
    for key in _SUBSCHEMA_MAPS:
        for name, sub in (schema.get(key) or {}).items():
            errors += check_schema(sub, f"{where}/{key}/{name}")
    for key in _SUBSCHEMA_LISTS:
        for i, sub in enumerate(schema.get(key) or []):
            errors += check_schema(sub, f"{where}/{key}/{i}")
    for key in _SUBSCHEMA_ONE:
        if key in schema:
            errors += check_schema(schema[key], f"{where}/{key}")
    for name in _as_list(schema.get("type")):
        if name not in _TYPES:
            errors.append(f"{where}: unknown type {name!r}")
    return errors


def _as_list(value: Any) -> list[Any]:
    return [] if value is None else value if isinstance(value, list) else [value]


def _pointer(doc: dict[str, Any], fragment: str) -> Any:
    node: Any = doc
    for part in [p for p in fragment.lstrip("/").split("/") if p]:
        node = node[part.replace("~1", "/").replace("~0", "~")]
    return node


def _equal(a: Any, b: Any) -> bool:
    if isinstance(a, bool) or isinstance(b, bool):
        return type(a) is type(b) and a == b
    return a == b


class _Validator:
    def __init__(self, root: dict[str, Any], resolve: Resolver | None) -> None:
        self.root = root
        self.resolve = resolve
        self.errors: list[str] = []

    def ref(self, ref: str, root: dict[str, Any]) -> tuple[Any, dict[str, Any]]:
        name, _, fragment = ref.partition("#")
        if name:
            if self.resolve is None:
                raise ValueError(f"cannot resolve $ref {ref!r}")
            root = self.resolve(name.rsplit("/", 1)[-1])
        return _pointer(root, fragment), root

    def run(self, schema: Any, value: Any, path: str, root: dict[str, Any]) -> list[str]:
        errors: list[str] = []
        if schema is True:
            return errors
        if schema is False:
            return [f"{path}: no value is allowed here"]
        if "$ref" in schema:
            target, target_root = self.ref(schema["$ref"], root)
            errors += self.run(target, value, path, target_root)
        types = _as_list(schema.get("type"))
        if types and not any(_TYPES[t](value) for t in types):
            return errors + [f"{path}: expected {' or '.join(types)}, got {_kind(value)}"]
        if "const" in schema and not _equal(value, schema["const"]):
            errors.append(f"{path}: must be {schema['const']!r}")
        if "enum" in schema and not any(_equal(value, v) for v in schema["enum"]):
            errors.append(f"{path}: must be one of {schema['enum']!r}")
        if isinstance(value, dict):
            errors += self.obj(schema, value, path, root)
        elif isinstance(value, list):
            errors += self.arr(schema, value, path, root)
        elif isinstance(value, str):
            errors += _string(schema, value, path)
        elif _TYPES["number"](value):
            if "minimum" in schema and value < schema["minimum"]:
                errors.append(f"{path}: below minimum {schema['minimum']}")
            if "maximum" in schema and value > schema["maximum"]:
                errors.append(f"{path}: above maximum {schema['maximum']}")
        for sub in schema.get("allOf", []):
            errors += self.run(sub, value, path, root)
        if "anyOf" in schema and all(self.run(s, value, path, root) for s in schema["anyOf"]):
            errors.append(f"{path}: matches none of anyOf")
        if "oneOf" in schema:
            hits = sum(not self.run(s, value, path, root) for s in schema["oneOf"])
            if hits != 1:
                errors.append(f"{path}: matches {hits} of oneOf, expected exactly 1")
        if "not" in schema and not self.run(schema["not"], value, path, root):
            errors.append(f"{path}: matches a schema it must not")
        return errors

    def obj(self, schema: dict, value: dict, path: str, root: dict) -> list[str]:
        errors = [f"{path}: missing required {k!r}" for k in schema.get("required", [])
                  if k not in value]  # fmt: skip
        props = schema.get("properties", {})
        patterns = schema.get("patternProperties", {})
        extra = schema.get("additionalProperties", True)
        for key, item in value.items():
            matched = False
            if key in props:
                matched = True
                errors += self.run(props[key], item, f"{path}/{key}", root)
            for pattern, sub in patterns.items():
                if re.search(pattern, key):
                    matched = True
                    errors += self.run(sub, item, f"{path}/{key}", root)
            if not matched:
                if extra is False:
                    errors.append(f"{path}: unexpected property {key!r}")
                elif extra is not True:
                    errors += self.run(extra, item, f"{path}/{key}", root)
        return errors

    def arr(self, schema: dict, value: list, path: str, root: dict) -> list[str]:
        errors: list[str] = []
        if len(value) < schema.get("minItems", 0):
            errors.append(f"{path}: fewer than {schema['minItems']} items")
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            errors.append(f"{path}: more than {schema['maxItems']} items")
        prefix = schema.get("prefixItems", [])
        for i, item in enumerate(value):
            sub = prefix[i] if i < len(prefix) else schema.get("items", True)
            errors += self.run(sub, item, f"{path}/{i}", root)
        return errors


def _string(schema: dict, value: str, path: str) -> list[str]:
    errors = []
    if len(value) < schema.get("minLength", 0):
        errors.append(f"{path}: shorter than {schema['minLength']}")
    if "maxLength" in schema and len(value) > schema["maxLength"]:
        errors.append(f"{path}: longer than {schema['maxLength']}")
    if "pattern" in schema and not re.search(schema["pattern"], value):
        errors.append(f"{path}: does not match {schema['pattern']!r}")
    return errors


def _kind(value: Any) -> str:
    return next((name for name, test in _TYPES.items() if test(value)), type(value).__name__)


def validate(schema: dict[str, Any], value: Any, resolve: Resolver | None = None) -> list[str]:
    """Every way *value* fails *schema*, as ``/json/pointer: reason`` lines; [] is valid."""
    return _Validator(schema, resolve).run(schema, value, "", schema)


__all__ = ["KEYWORDS", "check_schema", "validate"]
