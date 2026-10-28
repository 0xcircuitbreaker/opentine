"""``AdapterSpec``: a new harness importer in one file.

An adapter is a declarative record -- a name, an ``importer`` (a path or lines
in, :class:`~opentine.trace.schema.TraceEvent` list out), an optional
``detect`` predicate over one JSON record, the agent CLI's ``harness`` name for
its runs' ``opentine-agent/1`` identity, and an optional ``fixture`` (sample
lines) that ``tine harnesses --check`` runs it on. Every built-in transcript
importer is exposed as a spec too (:func:`builtin_specs`).

Third-party adapters are found through the ``opentine.adapters`` entry-point
group, but **loading one runs its code**, so none is imported unless its name is
in the user's allowlist, ``$XDG_CONFIG_HOME/opentine/adapters.json``
(``{"allow": ["name", ...]}``) -- a file in the user's own config directory, never
one a cloned repository can ship. An allowlisted adapter still cannot shadow a
built-in, and the core wrapper (:func:`run_adapter`) enforces what the adapter
cannot bypass: the source byte cap before it is called, a result that is a list
of ``TraceEvent`` within the event cap, and (in ``tine import``) the usual
distrust and re-pricing of any billing the source claims.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Callable
from dataclasses import dataclass
from importlib import metadata
from pathlib import Path
from typing import Any

from opentine.trace._transcript_common import MAX_EVENTS, MAX_SOURCE_BYTES
from opentine.trace.schema import TraceEvent

GROUP = "opentine.adapters"
NAME = re.compile(r"[a-z0-9][a-z0-9-]{0,47}")
MAX_ALLOWLIST_BYTES = 64 * 1024


@dataclass(frozen=True)
class AdapterSpec:
    name: str
    importer: Callable[[Any], list[TraceEvent]]
    harness: str = ""
    detect: Callable[[dict[str, Any]], bool] | None = None
    description: str = ""
    fixture: tuple[str, ...] = ()


def builtin_specs() -> dict[str, AdapterSpec]:
    from opentine._import_write import HARNESS_OF
    from opentine.trace._import_detect import TRANSCRIPT_IMPORTERS

    return {
        name: AdapterSpec(name, importer, harness=HARNESS_OF.get(name, ""), description="built-in")
        for name, importer in TRANSCRIPT_IMPORTERS.items()
    }


def allowlist_path() -> Path:
    home = os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config"
    return Path(home, "opentine", "adapters.json")


def allowlist() -> frozenset[str]:
    path = allowlist_path()
    try:
        if path.is_symlink():
            return frozenset()
        with open(path, "rb") as handle:
            data = json.loads(handle.read(MAX_ALLOWLIST_BYTES))
    except (OSError, ValueError, RecursionError):
        return frozenset()
    allowed = data.get("allow") if isinstance(data, dict) else None
    if not isinstance(allowed, list):
        return frozenset()
    return frozenset(item for item in allowed if isinstance(item, str) and NAME.fullmatch(item))


def problems(spec: Any) -> list[str]:
    """What is wrong with *spec* as a declaration (no code of it is run)."""
    if not isinstance(spec, AdapterSpec):
        return ["not an AdapterSpec"]
    found = []
    if not NAME.fullmatch(spec.name or ""):
        found.append("name must be lowercase letters, digits and dashes (1-48)")
    if not callable(spec.importer):
        found.append("importer is not callable")
    if spec.detect is not None and not callable(spec.detect):
        found.append("detect is not callable")
    if not isinstance(spec.fixture, tuple) or not all(isinstance(x, str) for x in spec.fixture):
        found.append("fixture must be a tuple of lines")
    return found


def external_specs(allowed: frozenset[str] | None = None) -> tuple[dict[str, AdapterSpec], dict]:
    """``(specs, skipped)``: allowlisted entry points loaded; the rest named, unloaded."""
    allowed = allowlist() if allowed is None else allowed
    builtins = set(builtin_specs())
    specs: dict[str, AdapterSpec] = {}
    skipped: dict[str, str] = {}
    for point in metadata.entry_points(group=GROUP):
        if point.name not in allowed:
            skipped[point.name] = "not allowlisted (not loaded)"
            continue
        if point.name in builtins:
            skipped[point.name] = "shadows a built-in (not loaded)"
            continue
        try:
            spec = point.load()
            spec = spec() if callable(spec) and not isinstance(spec, AdapterSpec) else spec
        except Exception as exc:  # noqa: BLE001 - third-party code; report, never crash
            skipped[point.name] = f"failed to load: {type(exc).__name__}"
            continue
        issues = problems(spec) or ([] if spec.name == point.name else ["name mismatch"])
        if issues:
            skipped[point.name] = "; ".join(issues)
        else:
            specs[spec.name] = spec
    return specs, skipped


def run_adapter(spec: AdapterSpec, source: Any) -> list[TraceEvent]:
    """*spec*'s importer on *source* under the core caps it cannot bypass."""
    if isinstance(source, (str, Path)):
        try:
            size = Path(source).stat().st_size
        except OSError:
            size = 0
        if size > MAX_SOURCE_BYTES:
            raise ValueError(f"source exceeds {MAX_SOURCE_BYTES} bytes")
    events = spec.importer(source)
    if not isinstance(events, list) or not all(isinstance(e, TraceEvent) for e in events):
        raise ValueError(f"adapter {spec.name!r} did not return a list of TraceEvent")
    if len(events) > MAX_EVENTS:
        raise ValueError(f"adapter {spec.name!r} exceeded {MAX_EVENTS} events")
    return events


def check(spec: AdapterSpec) -> list[str]:
    """Problems found declaring and (with a fixture) running *spec*; empty when fine."""
    found = problems(spec)
    if found or not spec.fixture:
        return found
    try:
        events = run_adapter(spec, list(spec.fixture))
    except Exception as exc:  # noqa: BLE001 - the check reports, it does not crash
        return [f"fixture import failed: {type(exc).__name__}: {str(exc)[:200]}"]
    return [] if events else ["fixture produced no events"]


def resolve(name: str) -> AdapterSpec:
    specs = {**builtin_specs(), **external_specs()[0]}
    if name not in specs:
        raise ValueError(
            f"no adapter {name!r}: built-ins and allowlisted entry points only "
            f"(allowlist: {allowlist_path()})"
        )
    return specs[name]


__all__ = [
    "GROUP",
    "AdapterSpec",
    "allowlist",
    "allowlist_path",
    "builtin_specs",
    "check",
    "external_specs",
    "problems",
    "resolve",
    "run_adapter",
]
