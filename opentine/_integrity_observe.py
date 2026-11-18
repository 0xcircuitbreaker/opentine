"""What one run touched, and the current digest of every pinned file (0.60).

:func:`touched` reads a stored run's tool steps: a file tool's path argument
(``file_path``, ``path``, ``notebook_path``, ``filename``, ``target_file``) is a
``write``, ``delete`` or ``read`` by the tool's name; a shell tool's command is
split for ``rm``/``git rm``/``unlink`` (delete), ``>``/``>>``/``tee``/``sed -i``
(write) and ``cat``/``head``/``tail``/``less`` (read) targets. Paths are made
relative to the repository root and written as posix. :func:`digests` hashes
every pinned file under the root (``None`` when it is gone). Both feed
:func:`opentine._integrity.check`.
"""

from __future__ import annotations

import hashlib
import shlex
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

from opentine._integrity import normalize

PATH_KEYS = ("file_path", "path", "notebook_path", "filename", "target_file")
WRITE_TOOLS = {"write", "edit", "multiedit", "notebookedit", "write_file", "edit_file",
               "create_file", "str_replace_editor", "str_replace", "apply_patch",
               "patch", "replace"}  # fmt: skip
DELETE_TOOLS = {"delete", "delete_file", "remove_file", "rm"}
READ_TOOLS = {"read", "read_file", "view", "open", "cat", "notebookread"}
SHELL_TOOLS = {"bash", "shell", "run_shell_command", "terminal", "exec", "execute_command"}
SHELL_ARGS = ("command", "cmd", "script")
_SHELL_OPS = {"rm": "delete", "unlink": "delete", "tee": "write", "cat": "read",
              "head": "read", "tail": "read", "less": "read", "more": "read"}  # fmt: skip


def relative(path: str, root: Path) -> str | None:
    """*path* relative to *root* as posix, or ``None`` when it lies outside."""
    text = str(path).strip()
    if not text:
        return None
    absolute = PurePosixPath(text).is_absolute() or PureWindowsPath(text).is_absolute()
    if not absolute:
        rel = normalize(text)
    else:
        try:
            rel = Path(text).resolve().relative_to(Path(root).resolve()).as_posix()
        except (ValueError, OSError):
            return None
    return None if rel.startswith("../") or rel == ".." or not rel else rel


def _shell(command: str) -> list[tuple[str, str]]:
    try:
        words = shlex.split(command, posix=True)
    except ValueError:
        words = command.split()
    out: list[tuple[str, str]] = []
    op: str | None = None
    skip = -1
    for i, word in enumerate(words):
        if i == skip:
            continue
        if word in ("&&", "||", ";", "|"):
            op = None
        elif word in (">", ">>") and i + 1 < len(words):
            out.append(("write", words[i + 1]))
            skip = i + 1
        elif word.startswith(">") and len(word.lstrip(">")) > 0:
            out.append(("write", word.lstrip(">")))
        elif op is None and word in _SHELL_OPS:
            op = _SHELL_OPS[word]
        elif op is None and word == "sed" and "-i" in words[i + 1 :]:
            op = "write-sed"
        elif word == "git" and i + 1 < len(words) and words[i + 1] == "rm":
            op = "delete"
        elif op and not word.startswith("-") and word != "rm":
            out.append(("write" if op == "write-sed" else op, word))
    return out


def _tool(step: Any) -> tuple[str, dict[str, Any]]:
    inputs = step.inputs if isinstance(step.inputs, dict) else {}
    name = inputs.get("name") or (step.tool_info or {}).get("name") or ""
    raw = next((inputs[k] for k in ("arguments", "input", "args") if k in inputs), None)
    args = raw if isinstance(raw, dict) else inputs
    return str(name).lower().rsplit("__", 1)[-1], args


def touched(run: Any, root: Path) -> list[dict[str, str]]:
    """``[{"path", "op", "step"}]`` for every file a run's tool calls touched."""
    out: set[tuple[str, str, str]] = set()
    for index, step in enumerate(run.steps):
        kind = step.v3_kind or getattr(step.kind, "value", str(step.kind))
        if kind != "tool":
            continue
        name, args = _tool(step)
        hits: list[tuple[str, str]] = []
        if name in SHELL_TOOLS:
            command = next((args[k] for k in SHELL_ARGS if isinstance(args.get(k), str)), "")
            hits = _shell(command)
        else:
            op = ("write" if name in WRITE_TOOLS else "delete" if name in DELETE_TOOLS
                  else "read" if name in READ_TOOLS else None)  # fmt: skip
            paths = [args[k] for k in PATH_KEYS if isinstance(args.get(k), str)]
            hits = [(op, p) for p in paths] if op else []
        for op, path in hits:
            rel = relative(path, root)
            if rel is not None:
                out.add((rel, op, str(index)))
    return [{"path": p, "op": o, "step": s} for p, o, s in sorted(out)]


def digests(protected: dict[str, Any], root: Path) -> dict[str, str | None]:
    """``{pinned path: sha256 hex | None}`` read under *root* (bytes, never text)."""
    out: dict[str, str | None] = {}
    for surface in protected["surfaces"]:
        for path in surface["pins"]:
            try:
                out[path] = hashlib.sha256((Path(root) / path).read_bytes()).hexdigest()
            except (FileNotFoundError, IsADirectoryError, NotADirectoryError):
                out[path] = None
    return dict(sorted(out.items()))


def pins(protected: dict[str, Any], root: Path) -> dict[str, dict[str, str]]:
    """``{surface: {path: hex}}`` for every file under *root* its globs or pins cover."""
    from opentine._integrity import matches

    root = Path(root)
    files = sorted(p.relative_to(root).as_posix() for p in root.rglob("*")
                   if p.is_file() and ".tine" not in p.relative_to(root).parts
                   and ".git" not in p.relative_to(root).parts)  # fmt: skip
    out: dict[str, dict[str, str]] = {}
    for surface in protected["surfaces"]:
        chosen = {f for f in files if any(matches(g, f) for g in surface["globs"])}
        chosen |= {p for p in surface["pins"] if (root / p).is_file()}
        out[surface["name"]] = {
            p: hashlib.sha256((root / p).read_bytes()).hexdigest() for p in sorted(chosen)
        }
    return out


__all__ = ["digests", "pins", "relative", "touched"]
