"""``tine-verify.pyz FILE`` for a project manifest, its history or a mirror state (0.46.1).

A JSON file holding one ``opentine.project`` manifest, a list of them (a
history, oldest first; ``tine project history --json`` writes ``versions``) or
one ``opentine.mirror-state``. A manifest or history passes when every version
is owner-signed and chained (``--pubkey`` pins the first owner). A mirror state
never passes: its one check reads ``host-statement`` and the report's verdict
is ``host-statement``, even when the host key (``--pubkey``) signed it.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from . import _project
from ._artifact import check as row

PROJECT = "opentine.project"
MIRROR = "opentine.mirror-state"


def _load(path: Path) -> Any:
    value = json.loads(path.read_text("utf-8"))
    if isinstance(value, dict) and isinstance(value.get("versions"), list):
        return value["versions"]
    return value


def kind(path: Path) -> str | None:
    """``project`` or ``mirror-state`` when *path* holds one; ``None`` else."""
    if path.suffix != ".json" or not path.is_file() or path.stat().st_size > 16 << 20:
        return None
    try:
        value = _load(path)
    except (OSError, ValueError, RecursionError):
        return None
    first = value[0] if isinstance(value, list) and value else value
    found = first.get("kind") if isinstance(first, dict) else None
    return (
        {PROJECT: "project", MIRROR: "mirror-state"}.get(found) if isinstance(found, str) else None
    )


def verify(path: Path, public_key: bytes | None) -> tuple[list[dict[str, Any]], str | None]:
    """``(checks, verdict override)`` for the project or mirror-state file at *path*."""
    value = _load(path)
    if kind(path) == "mirror-state":
        try:
            found = _project.mirror_verify(value, public_key)
        except _project.Refused as exc:
            return [row("mirror-state", "fail", exc.code, str(exc))], None
        check = row("mirror-state", "host-statement", "mirror.host-statement", found["label"],
                    **found)  # fmt: skip
        return [check], "host-statement"
    versions = value if isinstance(value, list) else [value]
    owner = public_key.hex() if public_key is not None else None
    try:
        found = (
            _project.project_chain(versions, owner)
            if len(versions) > 1
            or (versions and isinstance(versions[0], dict) and versions[0].get("seq") == 0)
            else _project.project_verify(versions[0], None, owner)
        )
    except _project.Refused as exc:
        return [row("project", "fail", exc.code, str(exc))], None
    return [row("project", "pass", "project.verified", PROJECT, **found)], None


__all__ = ["kind", "verify"]
