"""Which files are a harness's scaffold, and the signed list that overrides them (0.88).

The scaffold of an agent is every file its harness reads as configuration:
instruction files, settings, hooks, skills, commands, agent definitions, rules
and MCP configuration. :data:`DEFAULTS` derives each harness's globs from the
existing harness code -- the definition files of :mod:`opentine._agent_definition`
and the hook and proxy surfaces of :mod:`opentine._integrity_defaults` -- plus
the per-harness skill, command, agent and rule directories.

A repository can replace the list with ``.tine/scaffold/files.json``: an existing
``attestation`` whose claim follows ``opentine.scaffold-files/1``::

    {"schema": "opentine.scaffold-files/1", "harnesses": {NAME: [GLOB, ...]}}

signed by a ``policy``-role key from the owner-pinned trust bundle that is not
an ``optimizer`` key (the rule region pins use). A list that is filed but does
not verify is refused, never silently replaced by the defaults (fail closed).
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from opentine._agent_definition import HARNESS_FILES
from opentine._integrity_defaults import SURFACES

PIN = Path(".tine") / "scaffold" / "files.json"
SCHEMA = "opentine.scaffold-files/1"
MAX_GLOBS = 256
UNPINNED = "scaffold.files-unpinned"


class ScaffoldError(ValueError):
    """A scaffold list or manifest that cannot be used; ``code`` names why."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _surface(name: str) -> tuple[str, ...]:
    return next(globs for surface, _kind, globs in SURFACES if surface == name)


def _for(prefix: str, extra: tuple[str, ...]) -> tuple[str, ...]:
    """The hook and proxy surface globs under *prefix*, plus *extra*."""
    hooks = _surface("agent-hooks") + _surface("proxy-config")
    return tuple(g for g in hooks if g.startswith(prefix)) + extra


#: Instruction files whose ``@path`` lines import other files.
INSTRUCTIONS = frozenset({"CLAUDE.md", "CLAUDE.local.md", "AGENTS.md", "AGENTS.override.md",
                          "GEMINI.md"})  # fmt: skip

_CLAUDE = (*HARNESS_FILES["claude-code"], *_for(".claude/", ()), "CLAUDE.local.md",
           ".claude/CLAUDE.md", ".claude/agents/**", ".claude/commands/**",
           ".claude/skills/**", ".claude/rules/**", ".claude/output-styles/**")  # fmt: skip
_CODEX = (*HARNESS_FILES["codex"], *_for(".codex/", ()), "AGENTS.override.md",
          ".codex/prompts/**", ".codex/skills/**", ".agents/skills/**")  # fmt: skip
_GEMINI = (*HARNESS_FILES["gemini"], *_for(".gemini/", ()), ".gemini/commands/**",
           ".gemini/extensions/**", ".gemini/skills/**")  # fmt: skip
_OPENCODE = (*HARNESS_FILES["opencode"], "opencode.jsonc", ".opencode/agent/**",
             ".opencode/command/**", ".opencode/plugin/**", ".opencode/skill/**")  # fmt: skip
_CURSOR = (*_for(".cursor/", ()), "AGENTS.md", ".cursor/rules/**", ".cursor/commands/**")

DEFAULTS: dict[str, tuple[str, ...]] = {
    name: tuple(sorted(set(globs)))
    for name, globs in (
        ("claude-code", _CLAUDE),
        ("codex", _CODEX),
        ("gemini", _GEMINI),
        ("opencode", _OPENCODE),
        ("cursor", _CURSOR),
    )  # fmt: skip
}


def _clean(globs: Any) -> list[str]:
    from opentine._integrity import normalize

    if not isinstance(globs, list) or not 0 < len(globs) <= MAX_GLOBS:
        raise ScaffoldError(UNPINNED, f"a harness lists 1..{MAX_GLOBS} globs")
    out = []
    for glob in globs:
        if not isinstance(glob, str) or not glob or glob.startswith("/") or "\0" in glob:
            raise ScaffoldError(UNPINNED, f"a glob is a relative path pattern, not {glob!r}")
        norm = normalize(glob)
        if norm.split("/")[0] == "..":
            raise ScaffoldError(UNPINNED, f"glob {glob!r} climbs out of the root")
        out.append(norm)
    return sorted(set(out))


def _claim(doc: Any) -> dict[str, list[str]] | None:
    claim = doc.get("claim") if isinstance(doc, dict) else None
    if not isinstance(claim, dict) or claim.get("schema") != SCHEMA:
        return None
    harnesses = claim.get("harnesses")
    if not isinstance(harnesses, dict) or not harnesses or len(harnesses) > 64:
        return None
    try:
        return {str(n): _clean(g) for n, g in harnesses.items() if isinstance(n, str)}
    except ScaffoldError:
        return None


def pinned(root: Path) -> dict[str, list[str]] | None:
    """The signed list's harnesses, ``None`` when none is filed; refused when it fails."""
    from opentine import _json_shallow
    from opentine._integrity_run import _signer
    from opentine._regions_pin import _allowed

    try:
        raw = (Path(root) / PIN).read_bytes()
    except FileNotFoundError:
        return None
    try:
        doc = _json_shallow.loads(raw)
    except (ValueError, UnicodeDecodeError):
        doc = None
    claim = _claim(doc)
    if claim is None:
        raise ScaffoldError(UNPINNED, f"{PIN.as_posix()} is not an {SCHEMA} attestation")
    who = _signer(doc)
    if who is None:
        raise ScaffoldError(UNPINNED, "the scaffold list's signature does not verify")
    allowed, why = _allowed(Path(root))
    if who not in allowed:
        raise ScaffoldError(UNPINNED, why or f"signed by {who}, not a policy-role key")
    return claim


def globs(harness: str, root: Path) -> tuple[list[str], str]:
    """``(globs, source)`` for *harness*: the signed list's (``pinned``) or the defaults."""
    found = pinned(Path(root))
    if found is not None:
        if harness not in found:
            raise ScaffoldError(UNPINNED, f"the signed scaffold list names no {harness!r}")
        return found[harness], "pinned"
    if harness not in DEFAULTS:
        raise ScaffoldError(
            "scaffold.unknown-harness",
            f"no scaffold list for {harness!r}; known: {', '.join(DEFAULTS)}",
        )
    return list(DEFAULTS[harness]), "default"


def pin(root: Path, harnesses: dict[str, list[str]], key: Any, at: str) -> dict[str, Any]:
    """Sign and file the list; refused for a key that is not a policy-role key."""
    from opentine._integrity_run import _dump, _sign
    from opentine._promote import _who
    from opentine._regions_pin import _allowed
    from opentine.kernel import canonical_json

    cleaned = {name: _clean(g) for name, g in sorted(harnesses.items())}
    if not cleaned:
        raise ScaffoldError(UNPINNED, "name at least one --harness with its globs")
    allowed, why = _allowed(Path(root))
    if _who(key) not in allowed:
        raise ScaffoldError(UNPINNED, why or f"{_who(key)} is not a policy-role key")
    claim = {"schema": SCHEMA, "harnesses": cleaned}
    digest = hashlib.sha256(canonical_json(claim)).hexdigest()
    document = _sign(key, claim, f"sha256:{digest}", at)
    _dump(Path(root) / PIN, document)
    return {"harnesses": cleaned, "signer": document["signer"],
            "pin": (Path(root) / PIN).as_posix()}  # fmt: skip


__all__ = ["DEFAULTS", "INSTRUCTIONS", "PIN", "SCHEMA", "UNPINNED", "ScaffoldError", "globs",
           "pin", "pinned"]  # fmt: skip
