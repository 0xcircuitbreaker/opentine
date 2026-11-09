"""The plugin allow-list: ``$XDG_CONFIG_HOME/opentine/plugins.json`` (0.47).

Only the *user's* configuration directory is read. A repository, the current
directory or an environment variable naming a file cannot add a plugin: a
cloned repository is untrusted input and must never decide what code runs.

The file is ``opentine-plugin-allow/1``::

    {"schema": "opentine-plugin-allow/1",
     "allow": [{"kind": "scorer", "name": "toxicity",
                "distribution": "acme-scorers", "version": "1.2.0"}]}

An entry pins the entry point's kind and name *and* the distribution that
provides it at an exact version, so upgrading or swapping the package that
provides a name needs a new entry. On POSIX a file (or its directory) that
other users may write is refused, as ``ssh`` refuses such a config.
"""

from __future__ import annotations

import json
import os
import re
import stat
from pathlib import Path
from typing import Any

SCHEMA = "opentine-plugin-allow/1"
KINDS = ("importer", "signer", "scorer", "snapshot")
MAX_ENTRIES = 256
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+!_-]{0,63}$")


class AllowListError(ValueError):
    """The allow-list file is unreadable, malformed or unsafely writable."""


def path() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "opentine" / "plugins.json"


def normalize(distribution: str) -> str:
    """PEP 503 normalisation, so ``Acme_Scorers`` and ``acme-scorers`` are one name."""
    return re.sub(r"[-_.]+", "-", distribution).lower()


def _check_entry(entry: Any) -> dict[str, str]:
    if not isinstance(entry, dict) or set(entry) != {"kind", "name", "distribution", "version"}:
        raise AllowListError("an allow entry is {kind, name, distribution, version}")
    if entry["kind"] not in KINDS:
        raise AllowListError(f"unknown plugin kind {entry['kind']!r}; one of {', '.join(KINDS)}")
    for key, pattern in (("name", _NAME), ("distribution", _NAME), ("version", _VERSION)):
        if not isinstance(entry[key], str) or not pattern.fullmatch(entry[key]):
            raise AllowListError(f"allow entry {key} {entry[key]!r} is not a plain name")
    return {**entry, "distribution": normalize(entry["distribution"])}


def _writable_by_others(target: Path) -> bool:
    """POSIX: group/world writable, or owned by someone other than us (or root).

    A sticky world-writable directory still counts as unsafe: anyone may
    create the file in it, so who owns the file matters, and ownership is
    checked too (``ssh`` refuses a config owned by another user).
    """
    if os.name != "posix":
        return False
    info = target.stat()
    if info.st_uid not in (os.getuid(), 0):
        return True
    return bool(info.st_mode & (stat.S_IWGRP | stat.S_IWOTH))


def load() -> list[dict[str, str]]:
    """The allow entries; ``[]`` when the file does not exist."""
    target = path()
    if not target.is_file():
        return []
    for item in (target, target.parent):
        if _writable_by_others(item):
            raise AllowListError(f"{item.as_posix()} is writable by other users; refusing it")
    try:
        document = json.loads(target.read_text("utf-8"))
    except (OSError, ValueError) as exc:
        raise AllowListError(f"cannot read {target.as_posix()}: {exc}") from exc
    if not isinstance(document, dict) or document.get("schema") != SCHEMA:
        raise AllowListError(f"{target.as_posix()} is not {SCHEMA}")
    entries = document.get("allow")
    if not isinstance(entries, list) or len(entries) > MAX_ENTRIES:
        raise AllowListError(f"allow must be a list of at most {MAX_ENTRIES} entries")
    return [_check_entry(entry) for entry in entries]


def add(kind: str, name: str, distribution: str, version: str) -> dict[str, str]:
    """Append (or keep) one entry and write the file with owner-only permissions."""
    entry = _check_entry(
        {"kind": kind, "name": name, "distribution": distribution, "version": version}
    )
    entries = [e for e in load() if (e["kind"], e["name"]) != (kind, name)] + [entry]
    target = path()
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    body = {"schema": SCHEMA, "allow": sorted(entries, key=lambda e: (e["kind"], e["name"]))}
    temp = target.with_suffix(".json.tmp")
    temp.write_text(json.dumps(body, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if os.name == "posix":
        temp.chmod(0o600)
    os.replace(temp, target)
    return entry


__all__ = ["KINDS", "SCHEMA", "AllowListError", "add", "load", "normalize", "path"]
