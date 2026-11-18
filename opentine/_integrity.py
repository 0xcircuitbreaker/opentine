"""Protected surfaces of a self-improving agent loop (0.60): the pure check.

``.tine/protected.toml`` names the measuring sticks a run may not touch --
graders, tests, holdout manifests, sandbox policy, scorer code -- as globs
with pinned sha256 digests::

    version = 1
    [[surface]]
    name = "graders"
    kind = "grader"            # grader | test | holdout | sandbox | scorer
    globs = ["evals/graders/**"]
    [surface.pins]
    "evals/graders/judge.py" = "<64 hex>"

:func:`check` judges one run's *observations* -- the files its tool calls
touched (``write``, ``delete``, ``read``) and the current digest of every
pinned file -- against that list. It takes plain data, so the TS port
(``ts/verifier/src/protected.ts``) answers the shared fixture
``tests/data/integrity_check.json`` identically. Codes (owner decision D12):

``fail:protected-surface-modified``  a hash fact: a pinned file's digest is not
                                     its pin (or it is gone), or a write or
                                     delete tool call targets a protected path;
``advisory:test-deleted``            a delete tool call on a ``test`` surface;
``advisory:holdout-read``            a read tool call on a ``holdout`` surface.

Only ``fail:`` blocks; an ``advisory:`` is reported and never blocks by default.
These are ``tine integrity`` codes; ``tine verify`` and the pyz are unchanged.
"""

from __future__ import annotations

import re
import tomllib
from typing import Any

KINDS = ("grader", "test", "holdout", "sandbox", "scorer")
MODIFIED = "fail:protected-surface-modified"
TEST_DELETED = "advisory:test-deleted"
HOLDOUT_READ = "advisory:holdout-read"
OPS = ("write", "delete", "read")
_HEX = re.compile(r"[0-9a-f]{64}")
_NAME = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
MAX_SURFACES = 256
MAX_PINS = 100_000
_FOLD = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")


class ProtectedError(ValueError):
    """A protected-surfaces file that cannot be used (a policy fact)."""


def normalize(path: str) -> str:
    """A repository-relative posix path: ``\\`` is ``/``; ``.``, doubles and ``x/..`` go.

    A ``..`` that climbs above the root is kept, so the path stays outside.
    """
    parts: list[str] = []
    for part in path.replace("\\", "/").split("/"):
        if part in ("", "."):
            continue
        if part == ".." and parts and parts[-1] != "..":
            parts.pop()
        else:
            parts.append(part)
    return "/".join(parts)


def fold(text: str) -> str:
    """ASCII lower case, the same in the TS port (case-insensitive file systems)."""
    return text.translate(_FOLD)


# Files that hold the trust root itself: a run that writes or deletes them is a
# protected-surface fact whether or not the list names them.
CONTROL = (".tine/protected.toml", ".tine/key-roles.toml", ".tine/trust-bundle.note",
           ".tine/integrity/**")  # fmt: skip


def glob_regex(pattern: str) -> str:
    """``**`` spans directories, ``*`` and ``?`` stay inside one; nothing else is special."""
    out, i = [], 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return "^" + "".join(out) + "$"


def matches(pattern: str, path: str) -> bool:
    """Glob match, ASCII case-insensitive: ``Tests/X.py`` is ``tests/x.py`` on Windows."""
    regex = glob_regex(fold(normalize(pattern)))
    return re.match(regex, fold(normalize(path)), re.DOTALL) is not None


def parse(data: bytes) -> dict[str, Any]:
    """``{"version": 1, "surfaces": [{name, kind, globs, pins}]}``, sorted and checked."""
    try:
        document = tomllib.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ProtectedError(f"protected.toml is not TOML: {exc}") from exc
    if set(document) - {"version", "surface"} or document.get("version") != 1:
        raise ProtectedError("protected.toml needs version = 1 and only [[surface]] tables")
    given = document.get("surface", [])
    if not isinstance(given, list) or len(given) > MAX_SURFACES:
        raise ProtectedError(f"[[surface]] is a list of at most {MAX_SURFACES} tables")
    surfaces, names, pins = [], set(), 0
    for row in given:
        if not isinstance(row, dict) or set(row) - {"name", "kind", "globs", "pins"}:
            raise ProtectedError("a [[surface]] has only name, kind, globs and pins")
        name, kind = row.get("name"), row.get("kind")
        if not isinstance(name, str) or not _NAME.fullmatch(name) or name in names:
            raise ProtectedError(f"surface name {name!r} must be unique and [a-z0-9._-]")
        if kind not in KINDS:
            raise ProtectedError(f"surface {name}: kind must be one of {', '.join(KINDS)}")
        globs = row.get("globs", [])
        if not isinstance(globs, list) or not all(isinstance(g, str) and g for g in globs):
            raise ProtectedError(f"surface {name}: globs is a list of patterns")
        table = row.get("pins", {})
        if not isinstance(table, dict):
            raise ProtectedError(f"surface {name}: pins is a table of path = sha256 hex")
        pinned = {}
        for path, digest in table.items():
            if not isinstance(digest, str) or not _HEX.fullmatch(digest):
                raise ProtectedError(f"surface {name}: pin {path!r} is not 64 hex")
            pinned[normalize(path)] = digest
        pins += len(pinned)
        if pins > MAX_PINS:
            raise ProtectedError(f"protected.toml pins more than {MAX_PINS} files")
        names.add(name)
        surfaces.append({"name": name, "kind": kind,
                         "globs": sorted({normalize(g) for g in globs}),
                         "pins": dict(sorted(pinned.items()))})  # fmt: skip
    if not surfaces:
        raise ProtectedError("protected.toml names no [[surface]]")
    return {"version": 1, "surfaces": sorted(surfaces, key=lambda s: s["name"])}


def surfaces_of(protected: dict[str, Any], path: str) -> list[dict[str, Any]]:
    """The surfaces whose globs or pins cover *path*."""
    path = fold(normalize(path))
    return [s for s in protected["surfaces"]
            if path in {fold(p) for p in s["pins"]}
            or any(matches(g, path) for g in s["globs"])]  # fmt: skip


def _finding(code: str, surface: str, path: str, detail: str) -> dict[str, str]:
    return {"level": code.split(":", 1)[0], "code": code, "surface": surface, "path": path,
            "detail": detail}  # fmt: skip


def check(protected: dict[str, Any], observations: dict[str, Any]) -> list[dict[str, str]]:
    """Findings, sorted and de-duplicated, for one run's observations.

    *observations* is ``{"touched": [{"path", "op", "step"}], "digests": {path:
    hex | None}}``. A pin whose path is absent from ``digests`` was not observed
    and is not judged.
    """
    found: dict[tuple, dict[str, str]] = {}

    def add(code: str, surface: str, path: str, detail: str) -> None:
        row = _finding(code, surface, path, detail)
        found[(code, path, surface, detail)] = row

    digests = observations.get("digests") or {}
    for surface in protected["surfaces"]:
        for path, pin in surface["pins"].items():
            if path not in digests:
                continue
            now = digests[path]
            if now is None:
                add(MODIFIED, surface["name"], path, "pinned file is missing")
            elif now != pin:
                add(MODIFIED, surface["name"], path, f"sha256 {now} is not the pin {pin}")
    for row in observations.get("touched") or []:
        path, op, step = normalize(row["path"]), row["op"], str(row.get("step", ""))
        if op in ("write", "delete") and any(matches(g, path) for g in CONTROL):
            add(MODIFIED, "protected-list", path, f"{op} tool call at step {step}")
        for surface in surfaces_of(protected, path):
            name = surface["name"]
            if op in ("write", "delete"):
                add(MODIFIED, name, path, f"{op} tool call at step {step}")
            if op == "delete" and surface["kind"] == "test":
                add(TEST_DELETED, name, path, f"test deleted at step {step}")
            if op == "read" and surface["kind"] == "holdout":
                add(HOLDOUT_READ, name, path, f"holdout read at step {step}")
    return [found[k] for k in sorted(found)]


def blocking(findings: list[dict[str, str]], *, strict: bool = False) -> list[dict[str, str]]:
    """Every ``fail:``; ``advisory:`` only when *strict* (D12)."""
    return [f for f in findings if f["level"] == "fail" or (strict and f["level"] == "advisory")]


__all__ = ["CONTROL", "HOLDOUT_READ", "KINDS", "MODIFIED", "OPS", "TEST_DELETED", "ProtectedError",
           "blocking", "check", "fold", "glob_regex", "matches", "normalize", "parse",
           "surfaces_of"]  # fmt: skip
