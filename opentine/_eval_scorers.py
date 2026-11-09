"""Eval scorers: exact, regex, json-schema, a Python callable, and an LLM judge (0.45).

``parse(spec)`` turns a ``--scorer`` value into a :class:`Scorer`:

* ``exact`` -- 1 when the output equals ``expected`` (strings compared stripped);
* ``regex:PATTERN`` -- 1 when PATTERN matches the output (``re.search``);
* ``json-schema:FILE`` -- 1 when the output (JSON text or a value) satisfies a
  JSON Schema subset: type, enum, const, required, properties,
  additionalProperties (bool), items, minimum, maximum, minLength, maxLength;
* ``python:MODULE:FUNC`` or ``python:FILE.py:FUNC`` -- ``FUNC(output, item)``
  returning a bool, a number in 0..1 or ``{"score": n}``; it must be deterministic;
* ``llm-judge:PROVIDER[:MODEL]`` -- ``_eval_judge``; the judge call is recorded
  as its own run, whose id the verdict carries as ``judge_run``;
* ``plugin:NAME`` (0.47) -- an allow-listed ``opentine.scorers`` entry point
  (:mod:`opentine.plugins`); ``score(output, item)`` returns what ``python`` does.

``version`` pins the configuration: ``1`` for exact, ``1+sha256:<16 hex>`` of
the pattern, schema, callable source, judge prompt and model, or the plugin's
distribution and version otherwise.
"""

from __future__ import annotations

import hashlib
import importlib
import importlib.util
import inspect
import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

SCORER_IDS = ("exact", "regex", "json-schema", "python", "llm-judge", "plugin")


class ScorerError(ValueError):
    """A scorer spec that cannot be built, or a scorer that misbehaved."""


@dataclass
class Scorer:
    id: str
    version: str
    func: Callable[[dict[str, Any], Any], tuple[float, str]]
    config: dict[str, Any] = field(default_factory=dict)

    def __call__(self, item: dict[str, Any], output: Any) -> tuple[float, str]:
        """``(score in 0..1, judge run or "")`` for *output* against *item*."""
        return self.func(item, output)


def _pin(*parts: str) -> str:
    joined = "\0".join(parts).encode("utf-8")
    return "1+sha256:" + hashlib.sha256(joined).hexdigest()[:16]


def _norm(value: Any) -> Any:
    return value.strip() if isinstance(value, str) else value


def _exact(item: dict[str, Any], output: Any) -> tuple[float, str]:
    return (1.0 if _norm(output) == _norm(item.get("expected")) else 0.0), ""


_TYPES: dict[str, Callable[[Any], bool]] = {
    "object": lambda v: isinstance(v, dict),
    "array": lambda v: isinstance(v, list),
    "string": lambda v: isinstance(v, str),
    "boolean": lambda v: isinstance(v, bool),
    "null": lambda v: v is None,
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
    "number": lambda v: isinstance(v, int | float) and not isinstance(v, bool),
}


def conforms(value: Any, schema: Any) -> bool:
    """Whether *value* satisfies the supported JSON Schema subset."""
    if schema is True or schema == {}:
        return True
    if not isinstance(schema, dict):
        return schema is not False
    kinds = schema.get("type")
    if kinds is not None:
        names = kinds if isinstance(kinds, list) else [kinds]
        if not any(_TYPES.get(name, lambda _v: False)(value) for name in names):
            return False
    if "enum" in schema and value not in schema["enum"]:
        return False
    if "const" in schema and value != schema["const"]:
        return False
    if isinstance(value, dict):
        if any(name not in value for name in schema.get("required", [])):
            return False
        props = schema.get("properties", {})
        for name, item in value.items():
            if name in props:
                if not conforms(item, props[name]):
                    return False
            elif schema.get("additionalProperties") is False:
                return False
    if isinstance(value, list) and "items" in schema:
        for item in value:
            if not conforms(item, schema["items"]):
                return False
    if _TYPES["number"](value):
        if "minimum" in schema and value < schema["minimum"]:
            return False
        if "maximum" in schema and value > schema["maximum"]:
            return False
    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0) or len(value) > schema.get("maxLength", 1e18):
            return False
    return True


def _json_value(output: Any) -> Any:
    if isinstance(output, str):
        try:
            return json.loads(output)
        except ValueError:
            return output
    return output


def _callable(target: str) -> Callable[..., Any]:
    location, _, name = target.rpartition(":")
    if not location or not name:
        raise ScorerError("python scorer is python:MODULE:FUNC or python:FILE.py:FUNC")
    if location.endswith(".py"):
        spec = importlib.util.spec_from_file_location(Path(location).stem, location)
        if spec is None or spec.loader is None:
            raise ScorerError(f"cannot load {location}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    else:
        module = importlib.import_module(location)
    func = getattr(module, name, None)
    if not callable(func):
        raise ScorerError(f"{target} is not a callable")
    return func


def _plugin(name: str) -> Scorer:
    from opentine import plugins

    try:
        loaded = plugins.load("scorer", name)
        found = [c for c in plugins.discover(("scorer",)) if c.name == name and c.allowed]
    except (plugins.PluginError, ValueError) as exc:
        raise ScorerError(str(exc)) from exc
    if len(found) != 1:
        raise ScorerError(f"scorer plugin {name!r} changed while loading")
    pinned = found[0]
    return Scorer("plugin", _pin("plugin", name, pinned.distribution, pinned.version),
                  lambda i, out: (coerce(loaded.score(out, i)), ""))  # fmt: skip


def coerce(value: Any) -> float:
    """A scorer's return value as a score in 0..1."""
    if isinstance(value, dict):
        value = value.get("score")
    if isinstance(value, bool):
        return 1.0 if value else 0.0
    if isinstance(value, int | float) and 0 <= value <= 1:
        return float(value)
    raise ScorerError(f"a scorer returned {value!r}, not a bool or a number in 0..1")


def parse(spec: str, **judge: Any) -> Scorer:
    """The scorer a ``--scorer`` value names; *judge* configures ``llm-judge``."""
    kind, _, rest = spec.partition(":")
    if kind == "exact" and not rest:
        return Scorer("exact", "1", _exact)
    if kind == "regex" and rest:
        try:
            pattern = re.compile(rest)
        except re.error as exc:
            raise ScorerError(f"regex scorer pattern {rest!r}: {exc}") from exc
        return Scorer("regex", _pin(rest),
                      lambda _i, out: (1.0 if pattern.search(str(out)) else 0.0, ""))  # fmt: skip
    if kind == "json-schema" and rest:
        text = Path(rest).read_text("utf-8")
        schema = json.loads(text)
        return Scorer(
            "json-schema",
            _pin(json.dumps(schema, sort_keys=True)),
            lambda _i, out: (1.0 if conforms(_json_value(out), schema) else 0.0, ""),
        )
    if kind == "python" and rest:
        func = _callable(rest)
        try:
            source = inspect.getsource(func)
        except (OSError, TypeError):
            source = rest
        return Scorer("python", _pin(rest, source), lambda i, out: (coerce(func(out, i)), ""))
    if kind == "llm-judge" and rest:
        from opentine._eval_judge import judge_scorer

        return judge_scorer(rest, **judge)
    if kind == "plugin" and rest:
        return _plugin(rest)
    raise ScorerError(f"unknown scorer {spec!r}; one of: {', '.join(SCORER_IDS)}")


__all__ = ["SCORER_IDS", "Scorer", "ScorerError", "coerce", "conforms", "parse"]
