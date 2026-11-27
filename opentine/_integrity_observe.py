"""What one run touched, and the current digest of every pinned file (0.60).

:func:`touched` reads a stored run's tool steps: a file tool's path argument
(``file_path``, ``path``, ``notebook_path``, ``filename``, ``target_file``) is a
``write``, ``delete`` or ``read`` by the tool's name; a shell tool's command is
split for ``rm``/``git rm``/``unlink`` (delete), ``>``/``>>``/``tee``/``sed -i``
(write) and ``cat``/``head``/``tail``/``less`` (read) targets; setting or
unsetting an ``OPENTINE_*``/``TINE_*`` variable is a write to ``env:NAME``
(0.85). Paths are made
relative to the repository root and written as posix. :func:`digests` hashes
every pinned file under the root (``None`` when it is gone). Both feed
:func:`opentine._integrity.check`.
"""

from __future__ import annotations

import hashlib
import re
import shlex
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

from opentine._integrity import normalize
from opentine._integrity_defaults import env_touches

PATH_KEYS = ("file_path", "path", "notebook_path", "filename", "target_file", "file",
             "dest", "destination", "target", "source", "src", "new_path", "old_path",
             "paths", "files")  # fmt: skip
WRITE_TOOLS = {"write", "edit", "multiedit", "notebookedit", "write_file", "edit_file",
               "create_file", "str_replace_editor", "str_replace", "apply_patch",
               "patch", "replace"}  # fmt: skip
DELETE_TOOLS = {"delete", "delete_file", "remove_file", "rm"}
READ_TOOLS = {"read", "read_file", "view", "open", "cat", "notebookread"}
SHELL_TOOLS = {"bash", "shell", "run_shell_command", "terminal", "exec", "execute_command"}
SHELL_ARGS = ("command", "cmd", "script")
_SHELL_OPS = {"rm": "delete", "unlink": "delete", "shred": "delete", "tee": "write",
              "cp": "write-dest", "mv": "write", "install": "write-dest",
              "ln": "write", "rsync": "write-dest", "truncate": "write", "touch": "write",
              "chmod": "write",
              "patch": "write", "cat": "read", "head": "read", "tail": "read",
              "less": "read", "more": "read"}  # fmt: skip
# Inline code (python -c, perl -e, node -e, sh -c ...) is opaque: any path-like
# token in it counts as a write when the code also says it writes.
_INLINE = {"-c", "-e", "-pe", "-pie", "-i", "--eval", "-ne"}
_WRITE_WORDS = re.compile(r"write|unlink|remove|rename|replace|rmtree|truncate|copy|"
                          r"move|chmod|symlink|open\([^)]*['\"][wax+]|>\s*\S")  # fmt: skip
_TOKEN = re.compile(r"[A-Za-z0-9_.\\/-]+")
_WRITE_HINTS = ("write", "edit", "save", "create", "put", "patch", "replace", "move",
                "rename", "copy", "append", "update", "insert", "mkdir")  # fmt: skip
_DELETE_HINTS = ("delete", "remove", "unlink", "rmdir")


def relative(path: str, root: Path) -> str | None:
    """*path* relative to *root* as posix, or ``None`` when it lies outside."""
    text = str(path).strip()
    if not text:
        return None
    absolute = PurePosixPath(text).is_absolute() or PureWindowsPath(text).is_absolute()
    if not absolute:
        rel = normalize(text)
        try:  # a symlink still on disk names the file it points at
            real = (Path(root) / rel).resolve().relative_to(Path(root).resolve()).as_posix()
            rel = real if real != rel and real != "." else rel
        except (ValueError, OSError):
            pass
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
    dest: list[str] = []
    skip = -1
    for i, word in enumerate(words):
        if i == skip:
            continue
        if word in ("&&", "||", ";", "|"):
            if op == "write-dest" and dest:
                out.append(("write", dest[-1]))
            op, dest = None, []
        elif word in (">", ">>") and i + 1 < len(words):
            out.append(("write", words[i + 1]))
            skip = i + 1
        elif word.startswith(">") and len(word.lstrip(">")) > 0:
            out.append(("write", word.lstrip(">")))
        elif op is None and word in _SHELL_OPS:
            op = _SHELL_OPS[word]
        elif (
            op is None
            and word in ("sed", "perl")
            and any(w.startswith("-i") or w.startswith("-pi") for w in words[i + 1 :])
        ):
            op = "write-sed"
        elif word.startswith("of=") and word[3:]:
            out.append(("write", word[3:]))
        elif word == "git" and i + 1 < len(words) and words[i + 1] in (
            "checkout", "restore", "mv", "apply", "reset", "stash", "am",
        ):  # fmt: skip
            op = "write"
        elif word == "git" and i + 1 < len(words) and words[i + 1] == "rm":
            op = "delete"
        elif op == "write-dest" and not word.startswith("-"):
            dest.append(word)
        elif (
            op
            and not word.startswith("-")
            and word not in ("rm", "checkout", "restore", "mv", "apply", "reset")
        ):
            out.append(("write" if op == "write-sed" else op, word))
        if word in _INLINE and i + 1 < len(words) and _WRITE_WORDS.search(words[i + 1]):
            out.extend(("write", t) for t in _TOKEN.findall(words[i + 1]) if "/" in t
                       or "\\" in t or "." in t)  # fmt: skip
    if op == "write-dest" and dest:
        out.append(("write", dest[-1]))
    for word in words:  # $(...) / backticks / nested sh -c bodies
        if word != command and any(m in word for m in ("$(", "`", " > ", ";")):
            out.extend(_shell(word.replace("$(", " ").replace("`", " ").replace(")", " ")))
    return out


def _tool(step: Any) -> tuple[str, dict[str, Any]]:
    inputs = step.inputs if isinstance(step.inputs, dict) else {}
    name = inputs.get("name") or (step.tool_info or {}).get("name") or ""
    raw = next((inputs[k] for k in ("arguments", "input", "args") if k in inputs), None)
    args = raw if isinstance(raw, dict) else inputs
    return str(name).lower().rsplit("__", 1)[-1], args


def _guess(name: str) -> str | None:
    """An unknown tool's op from its name: ``fs_save``, ``move_file``, ``rm_path``."""
    if any(h in name for h in _DELETE_HINTS):
        return "delete"
    if any(h in name for h in _WRITE_HINTS):
        return "write"
    return "read" if any(h in name for h in ("read", "view", "open", "get", "cat")) else None


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
            out.update((f"env:{n}", "write", str(index)) for n in env_touches(command))
        else:
            op = ("write" if name in WRITE_TOOLS else "delete" if name in DELETE_TOOLS
                  else "read" if name in READ_TOOLS else _guess(name))  # fmt: skip
            paths = [args[k] for k in PATH_KEYS if isinstance(args.get(k), str)]
            paths += [p for k in PATH_KEYS if isinstance(args.get(k), list)
                      for p in args[k] if isinstance(p, str)]  # fmt: skip
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
            if path.startswith("env:"):
                continue
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
