"""The plugin API: entry-point importers, signers, scorers and snapshot providers (0.47).

A plugin is a Python entry point in one of four groups:

=============  ========================  ==================================
kind           entry-point group         the loaded object must provide
=============  ========================  ==================================
``importer``   ``opentine.importers``    ``load(path) -> Run``
``signer``     ``opentine.signers``      ``sign(payload: bytes) -> bytes``,
                                         ``public_key() -> str``
``scorer``     ``opentine.scorers``      ``score(output, item) -> score``
``snapshot``   ``opentine.snapshots``    ``snapshot(path) -> dict``,
                                         ``restore(snapshot, path)``
=============  ========================  ==================================

Nothing is ever loaded automatically: importing opentine, running a command or
opening a repository never imports plugin code. :func:`discover` reads package
*metadata* only. :func:`load` imports one plugin, and only when every loading
rule (:mod:`opentine._plugins_rules`) passes: the user's allow-list pins it,
it is installed in this interpreter's site-packages, and the module the entry
point names resolves inside that same distribution (a same-named module in the
current directory or another path entry cannot shadow it).

These rules choose *which* code may run; they do not sandbox it. A loaded
plugin runs with the full rights of the ``tine`` process, so the allow-list is
the trust decision. ``OPENTINE_NO_PLUGINS=1`` turns loading off entirely.
"""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass
from importlib import metadata
from typing import Any

from opentine import _plugins_allow, _plugins_rules
from opentine._plugins_allow import KINDS

GROUPS: dict[str, str] = {
    "importer": "opentine.importers",
    "signer": "opentine.signers",
    "scorer": "opentine.scorers",
    "snapshot": "opentine.snapshots",
}
REQUIRED: dict[str, tuple[str, ...]] = {
    "importer": ("load",),
    "signer": ("sign", "public_key"),
    "scorer": ("score",),
    "snapshot": ("snapshot", "restore"),
}
DISABLE_ENV = "OPENTINE_NO_PLUGINS"


class PluginError(RuntimeError):
    """A plugin that may not be loaded, or that does not provide its interface."""


@dataclass(frozen=True)
class Candidate:
    """One discovered entry point and whether the loading rules let it load."""

    kind: str
    name: str
    value: str
    distribution: str
    version: str
    allowed: bool
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def disabled() -> bool:
    return os.environ.get(DISABLE_ENV, "").strip() not in ("", "0")


def _entries(kind: str) -> list[metadata.EntryPoint]:
    if kind not in GROUPS:
        raise PluginError(f"unknown plugin kind {kind!r}; one of {', '.join(KINDS)}")
    return sorted(metadata.entry_points(group=GROUPS[kind]), key=lambda e: (e.name, e.value))


def _assess(kind: str, entry: metadata.EntryPoint, allow: list[dict[str, str]]) -> Candidate:
    dist = entry.dist
    name = _plugins_allow.normalize(dist.metadata["Name"] or "") if dist else ""
    version = (dist.version or "") if dist else ""
    reason = "disabled by " + DISABLE_ENV if disabled() else _plugins_rules.refusal(
        kind, entry, name, version, allow
    )  # fmt: skip
    return Candidate(kind, entry.name, entry.value, name, version, not reason, reason or "ok")


def discover(kinds: tuple[str, ...] = KINDS) -> list[Candidate]:
    """Every installed plugin of *kinds*, with the loading verdict; imports nothing."""
    allow = _plugins_allow.load()
    return [_assess(kind, entry, allow) for kind in kinds for entry in _entries(kind)]


def load(kind: str, name: str) -> Any:
    """Import and return the plugin *name* of *kind*, or raise :class:`PluginError`."""
    found = [entry for entry in _entries(kind) if entry.name == name]
    if not found:
        raise PluginError(f"no {kind} plugin named {name!r} is installed")
    if len(found) > 1:
        raise PluginError(f"{len(found)} installed distributions provide {kind} {name!r}")
    try:
        verdict = _assess(kind, found[0], _plugins_allow.load())
    except _plugins_allow.AllowListError as exc:
        raise PluginError(str(exc)) from exc
    if not verdict.allowed:
        raise PluginError(f"{kind} plugin {name!r} not loaded: {verdict.reason}")
    try:
        loaded = found[0].load()
    except Exception as exc:  # a plugin's import failing must not take tine down
        raise PluginError(f"{kind} plugin {name!r} failed to import: {exc}") from exc
    missing = [attr for attr in REQUIRED[kind] if not callable(getattr(loaded, attr, None))]
    if missing:
        raise PluginError(f"{kind} plugin {name!r} does not provide {', '.join(missing)}")
    return loaded


__all__ = ["DISABLE_ENV", "GROUPS", "KINDS", "REQUIRED", "Candidate", "PluginError"]
__all__ += ["discover", "disabled", "load"]
