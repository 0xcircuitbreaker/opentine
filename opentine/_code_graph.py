"""``tine code-graph``: a code map of a repository (0.48), ``tine-graph/1``.

For every tracked source file (``git ls-files``; a plain directory walk when the
folder is no git work tree) the map lists its top-level and nested symbols
(``class``, ``function``, ``method``, ``type``) with 1-based lines, and its
imports; ``edges`` link a file to the files of this repository it imports
(Python modules and relative JS/TS specifiers).

The parser is **tree-sitter** for Python when the optional ``graph`` extra is
installed (``tree-sitter`` + ``tree-sitter-python``), and a regex outline
everywhere else and as the fallback: ``backend`` says which one each file got.
A regex outline is an outline, not a parse: a symbol inside a string can show
up, a symbol built at runtime cannot. Paths are POSIX and repository-relative;
files above :data:`MAX_FILE` bytes and binary files are skipped.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path, PurePosixPath
from typing import Any

from opentine import _code_graph_ts as ts

SCHEMA = "tine-graph/1"
MAX_FILE = 1 << 20
MAX_FILES = 20_000
LANGUAGES = {".py": "python", ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript",
             ".jsx": "javascript", ".ts": "typescript", ".tsx": "typescript", ".go": "go",
             ".rs": "rust", ".java": "java", ".kt": "kotlin", ".kts": "kotlin"}  # fmt: skip
_I = r"[A-Za-z_$][A-Za-z0-9_$]*"
_PUB = r"(?:pub(?:\([^)]*\))?\s+)?"
RULES: dict[str, tuple[tuple[str, re.Pattern[str]], ...]] = {
    "python": (("class", re.compile(rf"^(\s*)class\s+({_I})")),
               ("function", re.compile(rf"^(\s*)(?:async\s+)?def\s+({_I})"))),
    "javascript": (("class", re.compile(rf"^(\s*)(?:export\s+(?:default\s+)?)?class\s+({_I})")),
                   ("function", re.compile(
                       rf"^(\s*)(?:export\s+(?:default\s+)?)?(?:async\s+)?function\*?\s+({_I})")),
                   ("function", re.compile(
                       rf"^(\s*)(?:export\s+)?const\s+({_I})\s*=\s*(?:async\s+)?\([^)]*\)\s*=>"))),
    "go": (("function", re.compile(rf"^()func\s+(?:\([^)]*\)\s*)?({_I})")),
           ("type", re.compile(rf"^()type\s+({_I})"))),
    "rust": (("function", re.compile(rf"^(\s*){_PUB}(?:async\s+)?fn\s+({_I})")),
             ("type", re.compile(rf"^(\s*){_PUB}(?:struct|enum|trait)\s+({_I})"))),
    "java": (("class", re.compile(
        rf"^(\s*)(?:(?:public|private|protected|abstract|final|static)\s+)*"
        rf"(?:class|interface|enum|record)\s+({_I})")),),
    "kotlin": (("class", re.compile(
        rf"^(\s*)(?:(?:public|private|internal|abstract|open|data|sealed)\s+)*"
        rf"(?:class|interface|object)\s+({_I})")),
               ("function", re.compile(rf"^(\s*)(?:(?:public|private|internal|override)\s+)*"
                                       rf"fun\s+(?:<[^>]*>\s*)?({_I})"))),
}  # fmt: skip
RULES["typescript"] = RULES["javascript"] + (
    ("type", re.compile(rf"^(\s*)(?:export\s+)?(?:interface|type|enum)\s+({_I})")),
)
IMPORTS = {
    "python": re.compile(r"^\s*(?:from\s+(\.*[\w.]*)\s+import|import\s+([\w.]+))"),
    "javascript": re.compile(r"""(?:^\s*import\b[^'"]*|require\()\s*['"]([^'"]+)['"]"""),
    "go": re.compile(r'^\s*(?:import\s+)?(?:\w+\s+)?"([^"]+)"\s*$'),
    "rust": re.compile(r"^\s*use\s+([\w:]+)"),
    "java": re.compile(r"^\s*import\s+(?:static\s+)?([\w.]+)"),
    "kotlin": re.compile(r"^\s*import\s+([\w.]+)"),
}
IMPORTS["typescript"] = IMPORTS["javascript"]


def files(root: Path) -> list[str]:
    """Repository-relative POSIX paths of the source files under *root*."""
    done = subprocess.run(["git", "-C", root.as_posix(), "ls-files", "-z"],
                          capture_output=True, check=False)  # fmt: skip
    if done.returncode == 0:
        names = [n for n in done.stdout.decode("utf-8", "replace").split("\0") if n]
    else:
        names = []
        for folder, dirs, found in os.walk(root):
            dirs[:] = sorted(d for d in dirs if not d.startswith(".") and d != "node_modules")
            base = Path(folder).relative_to(root)
            names += [(base / name).as_posix() for name in found]
    keep = [n for n in names if PurePosixPath(n).suffix in LANGUAGES]
    return sorted(keep)[:MAX_FILES]


def outline(text: str, language: str) -> tuple[list[dict[str, Any]], list[str]]:
    """The regex outline: ``(symbols, imports)``."""
    symbols, imports, classes = [], [], []  # classes: (indent, name)
    for number, line in enumerate(text.splitlines(), start=1):
        for kind, pattern in RULES[language]:
            match = pattern.match(line)
            if not match:
                continue
            indent = len(match.group(1).expandtabs())
            while classes and classes[-1][0] >= indent:
                classes.pop()
            parent = classes[-1][1] if classes else None
            found = "method" if kind == "function" and parent else kind
            symbols.append({"name": match.group(2), "kind": found, "line": number,
                            "parent": parent})  # fmt: skip
            if kind == "class":
                classes.append((indent, match.group(2)))
            break
        hit = IMPORTS[language].search(line)
        if hit:
            imports.append(next(g for g in hit.groups() if g))
    return symbols, imports


def _target(path: str, spec: str, language: str, known: set[str]) -> str | None:
    if language == "python":
        dots = len(spec) - len(spec.lstrip("."))
        parts = [p for p in spec.lstrip(".").split(".") if p]
        base = list(PurePosixPath(path).parent.parts)
        if dots:
            base = base[: len(base) - (dots - 1)] if dots > 1 else base
            stem = base + parts
        else:
            stem = parts
        for guess in ("/".join(stem) + ".py", "/".join([*stem, "__init__.py"])):
            if guess in known:
                return guess
        return None
    if language in ("javascript", "typescript") and spec.startswith("."):
        joined = os.path.normpath(PurePosixPath(path).parent.joinpath(spec).as_posix())
        joined = joined.replace("\\", "/")
        for ext in ("", ".ts", ".tsx", ".js", ".mjs", "/index.ts", "/index.js"):
            if joined + ext in known:
                return joined + ext
        stem = joined.rsplit(".", 1)[0]
        for ext in (".ts", ".tsx"):
            if stem + ext in known:
                return stem + ext
    return None


def build(root: Path, only: list[str] | None = None) -> dict[str, Any]:
    """The ``tine-graph/1`` map of *root* (or of the files under *only*)."""
    names = files(root)
    if only:
        prefixes = [p.strip("/") for p in only]
        names = [n for n in names if any(n == p or n.startswith(p + "/") for p in prefixes)]
    known = set(names)
    out, edges, backends = [], [], set()
    for name in names:
        path = root / name
        try:
            raw = path.read_bytes() if path.stat().st_size <= MAX_FILE else None
        except OSError:
            continue
        if raw is None or b"\0" in raw[:8192]:
            continue
        text, language = raw.decode("utf-8", "replace"), LANGUAGES[PurePosixPath(name).suffix]
        parsed = ts.parse(raw, language)
        backend = "tree-sitter" if parsed is not None else "regex"
        symbols, imports = parsed if parsed is not None else outline(text, language)
        backends.add(backend)
        out.append({"path": name, "language": language, "backend": backend,
                    "symbols": symbols, "imports": imports})  # fmt: skip
        for spec in imports:
            target = _target(name, spec, language, known)
            if target and target != name:
                edges.append({"from": name, "to": target})
    unique = [dict(t) for t in sorted({tuple(e.items()) for e in edges})]
    backend = (
        "tree-sitter" if backends == {"tree-sitter"} else "mixed" if len(backends) > 1 else "regex"
    )
    return {"schema": SCHEMA, "backend": backend, "tree_sitter": ts.available(),
            "files": out, "edges": unique,
            "counts": {"files": len(out), "symbols": sum(len(f["symbols"]) for f in out),
                       "edges": len(unique)}}  # fmt: skip


__all__ = ["SCHEMA", "build", "files", "outline"]
