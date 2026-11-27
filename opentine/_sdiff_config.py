"""Config and tool-set diff (0.88), for ``tine lineage diff``.

A config file (JSON, TOML, YAML) is parsed and compared as canonical data:
every leaf by its path (``a.b[0]``), so reordered keys are not a change and a
``"1"`` that became ``1`` is. A repeated key is refused (:class:`DuplicateKey`):
with last-wins parsing two readers can see two configs in one file. YAML is
read only when PyYAML is installed (it is not a dependency); without it a YAML
file is diffed by tokens.

A JSON file is a *tool set* when it holds a list of tool definitions (a
``tools/list`` result, ``{"tools": [...]}`` or a bare list), each an object with
a ``name`` and one of ``inputSchema``, ``input_schema`` or ``parameters``. Tools
are compared by name and :func:`tool_def_digest`, so a tool that keeps its name
while its schema changes is ``changed``.
"""

from __future__ import annotations

import hashlib
import tomllib
from typing import Any

from opentine import _json_shallow
from opentine.kernel import canonical_json

CONFIG_SUFFIXES = (".json", ".toml", ".yaml", ".yml")
_SCHEMA_KEYS = ("inputSchema", "input_schema", "parameters")
TOOL_DOMAIN = b"opentine.tool-def.v1:"


class DuplicateKey(ValueError):
    """A config file repeats a key."""


class Unreadable(ValueError):
    """A config file does not parse (or its parser is not installed)."""


def tool_def_digest(definition: dict[str, Any]) -> str:
    """``sha256:`` over a domain and the JCS of one tool definition."""
    return "sha256:" + hashlib.sha256(TOOL_DOMAIN + canonical_json(definition)).hexdigest()


def _yaml(text: str) -> Any:
    try:
        import yaml
    except ImportError:
        raise Unreadable("PyYAML is not installed") from None

    class Loader(yaml.SafeLoader):
        pass

    def mapping(loader: Any, node: Any, deep: bool = False) -> dict[Any, Any]:
        out: dict[Any, Any] = {}
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node, deep=deep)
            if key in out:
                raise DuplicateKey(f"duplicate key {key!r}")
            out[key] = loader.construct_object(value_node, deep=deep)
        return out

    Loader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping)
    try:
        return yaml.load(text, Loader=Loader)  # noqa: S506 - SafeLoader subclass
    except DuplicateKey:
        raise
    except (yaml.YAMLError, RecursionError, TypeError) as exc:
        raise Unreadable(f"YAML does not parse: {exc}") from None


def parse(suffix: str, text: str) -> Any:
    """The parsed document; :class:`DuplicateKey` or :class:`Unreadable` otherwise."""
    if suffix == ".json":
        try:
            return _json_shallow.loads(text, object_pairs_hook=_json_shallow.unique_pairs)
        except ValueError as exc:
            if "duplicate key" in str(exc):
                raise DuplicateKey("duplicate key") from None
            raise Unreadable(f"JSON does not parse: {exc}") from None
        except RecursionError:
            raise Unreadable("JSON nests too deep") from None
    if suffix == ".toml":
        try:
            return tomllib.loads(text)
        except tomllib.TOMLDecodeError as exc:
            if "overwrite" in str(exc).lower() or "duplicate" in str(exc).lower():
                raise DuplicateKey(f"duplicate key: {exc}") from None
            raise Unreadable(f"TOML does not parse: {exc}") from None
    return _yaml(text)


def tools(doc: Any) -> dict[str, dict[str, Any]] | None:
    """``{name: definition}`` when *doc* is a tool set, else ``None``."""
    found = doc
    if isinstance(doc, dict):  # only a whole tools/list result: other keys are config
        inner = doc
        if set(doc) <= {"jsonrpc", "id", "result"} and isinstance(doc.get("result"), dict):
            inner = doc["result"]
        if not set(inner) <= {"tools", "nextCursor", "_meta"}:
            return None
        found = inner.get("tools")
    if not isinstance(found, list) or (not found and not isinstance(doc, dict)):
        return None
    out: dict[str, dict[str, Any]] = {}
    for item in found:
        if not (isinstance(item, dict) and isinstance(item.get("name"), str)
                and any(k in item for k in _SCHEMA_KEYS)):  # fmt: skip
            return None
        if item["name"] in out:
            raise DuplicateKey(f"tool {item['name']!r} is defined twice")
        out[item["name"]] = item
    return out


def _leaves(value: Any, path: str, out: dict[str, str]) -> None:
    if isinstance(value, dict) and value:
        for key in value:
            _leaves(value[key], f"{path}.{key}" if path else str(key), out)
    elif isinstance(value, list) and value:
        for index, item in enumerate(value):
            _leaves(item, f"{path}[{index}]", out)
    else:
        out[path or "(root)"] = canonical_json(_plain(value)).decode("utf-8")


def _plain(value: Any) -> Any:
    """TOML/YAML scalars JCS cannot encode (dates, times) as tagged strings."""
    if isinstance(value, (str, int, bool)) or value is None or value in ({}, []):
        return value
    if isinstance(value, float):
        return f"<float>{value!r}"
    return f"<{type(value).__name__}>{value.isoformat() if hasattr(value, 'isoformat') else value}"


def config_diff(before: Any, after: Any) -> list[dict[str, Any]]:
    from opentine._sdiff_text import shown

    old: dict[str, str] = {}
    new: dict[str, str] = {}
    _leaves(before, "", old)
    _leaves(after, "", new)
    changes = []
    for path in sorted(set(old) | set(new)):
        if path not in new:
            changes.append({"op": "removed", "item": shown(path, 200)})
        elif path not in old:
            changes.append({"op": "added", "item": shown(path, 200)})
        elif old[path] != new[path]:
            changes.append({"op": "changed", "item": shown(path, 200),
                            "before": shown(old[path]), "after": shown(new[path])})  # fmt: skip
    return changes


def tool_diff(before: dict[str, Any], after: dict[str, Any]) -> list[dict[str, Any]]:
    from opentine._sdiff_text import shown

    changes = []
    for name in sorted(set(before) | set(after)):
        a = tool_def_digest(before[name]) if name in before else None
        b = tool_def_digest(after[name]) if name in after else None
        if a != b:
            op = "added" if a is None else "removed" if b is None else "changed"
            changes.append({"op": op, "item": shown(name, 200), "before": a, "after": b})
    return changes


__all__ = ["CONFIG_SUFFIXES", "DuplicateKey", "Unreadable", "config_diff", "parse",
           "tool_def_digest", "tool_diff", "tools"]  # fmt: skip
