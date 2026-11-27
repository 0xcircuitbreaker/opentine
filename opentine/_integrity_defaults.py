"""Default protected surfaces for the oversight machinery (0.85).

A loop that can edit its own monitor config, oversight policy, policy files,
agent hook settings or proxy config can switch off what watches it, without
touching a grader. These surfaces are protected whether or not
``.tine/protected.toml`` names them: :func:`merged` adds them to the signed
list before :func:`opentine._integrity.check` runs, so a write or delete tool
call on one is ``fail:protected-surface-modified`` and a read of a ``monitor``
surface is ``advisory:protected-read``.

``env:NAME`` paths are environment variables a run's shell commands set or
unset (:func:`env_touches`): setting ``OPENTINE_*`` or ``TINE_*`` from inside a
run is a write to the ``monitor-env`` surface.

Default pins: ``tine oversight sign-policy``, ``tine mcp-proxy --monitor`` and
``tine hook install`` record the digest of the config file they wrote or read
in ``.tine/integrity/defaults.json`` (a control file: a run that writes it
trips the check). Pinned digests are judged like any pin. ``tine integrity pin``
folds the default surfaces and these pins into ``.tine/protected.toml``; the
policy-role signature over that list is the re-pin after a legitimate edit.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from opentine._integrity import normalize

DEFAULTS = Path(".tine") / "integrity" / "defaults.json"
SURFACES: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("oversight-policy", "oversight", (".tine/oversight.toml", ".tine/oversight.sig.json")),
    ("monitor-config", "monitor", (".tine/monitor*.toml", ".tine/monitor*.json",
                                   ".tine/monitors/**", "monitors/**")),
    ("policy-files", "policy", (".tine/policy/**", ".tine/policies/**", ".tine/*policy*.toml",
                                ".tine/*policy*.json", ".tine/*policy*.sig.json")),
    ("agent-hooks", "hook", (".claude/settings.json", ".claude/settings.local.json",
                             ".claude/hooks/**", ".codex/hooks.json", ".codex/config.toml",
                             ".gemini/settings.json", ".cursor/hooks.json", ".hermes/**")),
    ("proxy-config", "proxy", (".mcp.json", ".cursor/mcp.json", ".tine/mcp-proxy*",
                               ".tine/proxy*")),
    ("monitor-env", "monitor", ("env:OPENTINE_*", "env:TINE_*")),
)  # fmt: skip
ENV_PREFIXES = ("OPENTINE_", "TINE_")
_ENV = re.compile(
    r"(?:^|[\s;&|(`])(?:export\s+|setenv\s+|set\s+)?([A-Z][A-Z0-9_]*)=|"
    r"\bunset\s+([A-Z][A-Z0-9_ ]*)|\benv\s+-u\s*([A-Z][A-Z0-9_]*)|"
    r"environ(?:\[\s*['\"]|\.(?:pop|setdefault|update)\(\s*['\"])([A-Z][A-Z0-9_]*)|"
    r"\b(?:putenv|setenv|unsetenv|Set-Item\s+env:|\$env:)\(?\s*['\"]?([A-Z][A-Z0-9_]*)"
)


def env_touches(command: str) -> list[str]:
    """Monitoring-related environment variables a shell command sets or unsets."""
    names = {n for m in _ENV.finditer(command) for g in m.groups() if g for n in g.split()}
    return sorted(n for n in names if n.startswith(ENV_PREFIXES))


def recorded(root: Path) -> dict[str, dict[str, str]]:
    """``{path: {"kind", "sha256"}}`` from ``.tine/integrity/defaults.json`` (empty if none)."""
    from opentine._json_shallow import loads

    try:
        doc = loads((Path(root) / DEFAULTS).read_bytes())
    except (OSError, ValueError):
        return {}
    pins = doc.get("pins") if isinstance(doc, dict) else None
    if not isinstance(pins, dict) or doc.get("version") != 1:
        return {}
    kinds = {kind for _name, kind, _globs in SURFACES}
    return {
        normalize(p): {"kind": r["kind"], "sha256": r["sha256"]}
        for p, r in pins.items()
        if isinstance(r, dict)
        and r.get("kind") in kinds
        and isinstance(r.get("sha256"), str)
        and re.fullmatch(r"[0-9a-f]{64}", r["sha256"])
    }


def pin(root: Path, path: str | Path, kind: str) -> str | None:
    """Record the digest of *path* (inside *root*) as a default pin; its posix path or None."""
    root = Path(root)
    try:
        rel = Path(path).resolve().relative_to(root.resolve()).as_posix()
        digest = hashlib.sha256((root / rel).read_bytes()).hexdigest()
    except (ValueError, OSError):
        return None  # outside the repository, or not a file: nothing to pin here
    pins = recorded(root)
    pins[rel] = {"kind": kind, "sha256": digest}
    target = root / DEFAULTS
    target.parent.mkdir(parents=True, exist_ok=True)
    body = json.dumps({"version": 1, "pins": dict(sorted(pins.items()))}, indent=2,
                      sort_keys=True) + "\n"  # fmt: skip
    target.write_bytes(body.encode("utf-8"))
    return rel


def surfaces(root: Path | None) -> list[dict[str, Any]]:
    """The default surfaces, with any recorded pins, as parsed surface rows."""
    pins = recorded(root) if root is not None else {}
    home: dict[str, str] = {}
    for name, kind, globs in SURFACES:  # a pin goes to the first file surface of its kind
        if not globs[0].startswith("env:"):
            home.setdefault(kind, name)
    out = []
    for name, kind, globs in SURFACES:
        mine = {p: r["sha256"] for p, r in pins.items() if home.get(r["kind"]) == name}
        out.append({"name": name, "kind": kind, "globs": sorted(globs),
                    "pins": dict(sorted(mine.items()))})  # fmt: skip
    return out


def merged(protected: dict[str, Any], root: Path | None) -> dict[str, Any]:
    """*protected* plus each default surface whose name the list does not already use.

    A list surface with a default's name keeps its own globs; recorded pins are
    added to it, and the signed list's pin wins where both pin one path.
    """
    defaults = {s["name"]: s for s in surfaces(root)}
    rows = []
    for row in protected["surfaces"]:
        extra = defaults.pop(row["name"], {"pins": {}})["pins"]
        rows.append({**row, "pins": dict(sorted({**extra, **row["pins"]}.items()))})
    rows = sorted([*rows, *defaults.values()], key=lambda s: s["name"])
    return {**protected, "surfaces": rows}


__all__ = ["DEFAULTS", "ENV_PREFIXES", "SURFACES", "env_touches", "merged", "pin", "recorded",
           "surfaces"]  # fmt: skip
