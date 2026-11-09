"""JSON Schemas for the plugin API and ``tine experts`` (0.47).

``opentine-plugin-allow-1`` is the user's plugin allow-list file
(:mod:`opentine._plugins_allow`); it is local configuration, not an object
kind, and never travels in a repository. ``tine-cli-plugins-1`` is every
``tine plugins`` action's ``--json`` output and ``tine-experts-1`` is
``tine experts PATH --json``.
"""

from __future__ import annotations

from typing import Any

from opentine._schema_defs import BOOL, INT, NUM, STR, closed, doc, open_

_KIND = {"enum": ["importer", "signer", "scorer", "snapshot"]}
_PLAIN = {"type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"}
_VERSION = {"type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9.+!_-]{0,63}$"}
_CANDIDATE = closed(["kind", "name", "value", "distribution", "version", "allowed", "reason"], {
    "kind": _KIND, "name": STR, "value": STR, "distribution": STR, "version": STR,
    "allowed": BOOL, "reason": STR})  # fmt: skip
_EXPERT = closed(["rank", "kind", "id", "lines", "share", "files", "commits", "runs",
                  "verified_runs"], {
    "rank": {"type": "integer", "minimum": 1}, "kind": {"enum": ["agent", "human"]},
    "id": STR, "lines": INT, "share": {**NUM, "minimum": 0, "maximum": 1}, "files": INT,
    "commits": INT, "runs": INT, "verified_runs": INT})  # fmt: skip

SCHEMAS: dict[str, dict[str, Any]] = {
    "opentine-plugin-allow-1": doc("opentine-plugin-allow-1", "opentine-plugin-allow/1",
        "The plugin allow-list, read only from `$XDG_CONFIG_HOME/opentine/plugins.json`. "
        "Each entry pins an entry point (kind, name) to the distribution that provides it at "
        "an exact version; a plugin loads only when an entry matches (docs/PLUGINS.md).",
        closed(["schema", "allow"], {
            "schema": {"const": "opentine-plugin-allow/1"},
            "allow": {"type": "array", "maxItems": 256, "items": closed(
                ["kind", "name", "distribution", "version"], {
                    "kind": _KIND, "name": _PLAIN, "distribution": _PLAIN,
                    "version": _VERSION})}})),
    "tine-cli-plugins-1": doc("tine-cli-plugins-1", "tine plugins ACTION --json",
        "`list`: every installed entry point in the four plugin groups with the loading "
        "verdict (`allowed`, `reason`); `check`/`allow`: the one plugin named. Listing "
        "imports nothing. A refusal is the error envelope.",
        open_(["command", "action", "ok", "plugins"], {
            "command": {"const": "plugins"}, "action": {"enum": ["list", "check", "allow"]},
            "ok": BOOL, "plugins": {"type": "array", "items": _CANDIDATE}})),
    "tine-experts-1": doc("tine-experts-1", "tine-experts/1",
        "`tine experts PATH --json`: agents (by model, from line attribution notes) and "
        "humans (by commit author e-mail) ranked by attributed lines, then verified runs. "
        "`verified_runs` counts runs credited by notes whose signature checks and whose "
        "content hashes still match.",
        open_(["command", "schema", "path", "revision", "files", "files_clipped",
               "total_lines", "experts"], {
            "command": {"const": "experts"}, "schema": {"const": "tine-experts/1"},
            "path": STR, "revision": {"type": "string", "pattern": "^([0-9a-f]{40}|[0-9a-f]{64})$"},
            "files": INT, "files_clipped": BOOL, "total_lines": INT,
            "experts": {"type": "array", "items": _EXPERT}})),
}  # fmt: skip

COMMAND_SCHEMAS: dict[str, str] = {"plugins": "tine-cli-plugins-1", "experts": "tine-experts-1"}

__all__ = ["COMMAND_SCHEMAS", "SCHEMAS"]
