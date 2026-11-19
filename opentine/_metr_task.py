"""METR task-standard families -> an OpenTine eval dataset (0.64), without running them.

A task family is a directory holding ``<family>.py`` with ``class TaskFamily``
(``standard_version``, ``required_environment_variables``, a static
``get_tasks`` returning ``{task_name: task_data}``, ``get_permissions``) and,
optionally, ``manifest.yaml``. The family file is parsed with :mod:`ast` and
never imported or executed: only literal values are read. A ``get_tasks`` that
builds its dict at run time yields no tasks, and the result says so.

Each task becomes one dataset item (``tine eval`` reads it)::

    {"id": "<family>/<task>", "input": {"family", "task", "data"},
     "metadata": {"standard": "metr-task-standard", "standard_version",
                  "required_environment_variables", "permissions",
                  "family_sha256", "manifest_sha256"}}
"""

from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
from typing import Any

from opentine._eval_verdict import NAME_RE
from opentine._inspect_log import MAX_DEPTH

MAX_SOURCE_BYTES = 4 << 20
MAX_TASKS = 100_000


class MetrTaskError(ValueError):
    """A task family this reader refuses."""


def _literal(node: ast.AST | None) -> Any:
    if node is None:
        return None
    try:  # a literal only, as plain JSON (tuples become lists; sets, bytes: none)
        return json.loads(json.dumps(ast.literal_eval(node), allow_nan=False))
    except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
        return None


def _returned(function: ast.FunctionDef) -> Any:
    for node in function.body:
        if isinstance(node, ast.Return):
            return _literal(node.value)
    return None


def _family_class(tree: ast.Module) -> ast.ClassDef:
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == "TaskFamily":
            return node
    raise MetrTaskError("no class TaskFamily")


def _parse(source: bytes) -> dict[str, Any]:
    if len(source) > MAX_SOURCE_BYTES:
        raise MetrTaskError(f"family file larger than {MAX_SOURCE_BYTES} bytes")
    try:
        tree = ast.parse(source.decode("utf-8"))
    except (UnicodeDecodeError, SyntaxError, ValueError, RecursionError, MemoryError) as exc:
        raise MetrTaskError(f"family file does not parse ({type(exc).__name__})") from exc
    family = _family_class(tree)
    out: dict[str, Any] = {"standard_version": None, "required_environment_variables": [],
                           "tasks": None, "permissions": None}  # fmt: skip
    for node in family.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            name = getattr(node.targets[0], "id", None)
            if name in ("standard_version", "required_environment_variables"):
                out[name] = _literal(node.value)
        elif isinstance(node, ast.FunctionDef) and node.name == "get_tasks":
            out["tasks"] = _returned(node)
        elif isinstance(node, ast.FunctionDef) and node.name == "get_permissions":
            out["permissions"] = _returned(node)
    return out


def _depth(value: Any, depth: int = 0) -> None:
    if depth > MAX_DEPTH:
        raise MetrTaskError(f"task data nested deeper than {MAX_DEPTH}")
    for child in (
        value.values() if isinstance(value, dict) else value if isinstance(value, list) else ()
    ):
        _depth(child, depth + 1)


def read_family(folder: str | Path) -> dict[str, Any]:
    """``{family, items, dynamic}`` for the task family in *folder*."""
    folder = Path(folder)
    name = folder.name
    path = folder / f"{name}.py"
    if not path.is_file():
        raise MetrTaskError(f"{folder}: no {name}.py task family file")
    with open(path, "rb") as handle:
        source = handle.read(MAX_SOURCE_BYTES + 1)
    parsed = _parse(source)
    manifest = folder / "manifest.yaml"
    manifest_sha = None
    if manifest.is_file():
        with open(manifest, "rb") as handle:
            manifest_sha = "sha256:" + hashlib.sha256(handle.read(MAX_SOURCE_BYTES)).hexdigest()
    tasks = parsed["tasks"]
    if tasks is not None and not isinstance(tasks, dict):
        raise MetrTaskError("get_tasks must return a dict")
    tasks = tasks or {}
    if len(tasks) > MAX_TASKS:
        raise MetrTaskError(f"more than {MAX_TASKS} tasks")
    env = parsed["required_environment_variables"]
    meta = {"standard": "metr-task-standard", "standard_version": parsed["standard_version"],
            "required_environment_variables": env if isinstance(env, list) else [],
            "family_sha256": "sha256:" + hashlib.sha256(source).hexdigest(),
            "manifest_sha256": manifest_sha}  # fmt: skip
    if isinstance(parsed["permissions"], list):
        meta["permissions"] = parsed["permissions"]
    items = []
    for task, data in sorted(tasks.items(), key=lambda pair: str(pair[0])):
        ident = f"{name}/{task}"
        if not isinstance(task, str) or not NAME_RE.fullmatch(ident):
            raise MetrTaskError(f"task name {task!r} is not 1..256 safe characters")
        _depth(data)
        items.append({"id": ident, "input": {"family": name, "task": task, "data": data},
                      "metadata": meta})  # fmt: skip
    return {"family": name, "items": items, "dynamic": parsed["tasks"] is None}


__all__ = ["MetrTaskError", "read_family"]
