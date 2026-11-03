"""0.28: ``tine fork --set PATH=VALUE`` — fork a run with step K's input edited.

The fork keeps every step before K exactly as recorded and replaces K with an
edited copy whose recorded result is cleared (it was never executed). The edit
enters the fork id through the fork *intent* (so two different edits of the
same point are two different runs) and is spelled out in ``metadata["edit"]``:
which step, which fields, and the SHA-256 of each old and new value — so
provenance shows the run was edited without copying a prompt into the record.
The source run is only read, never written.
"""

from __future__ import annotations

import argparse
import copy
import dataclasses
import hashlib
import json
from pathlib import Path
from typing import Any

from opentine._canon import _canonical_bytes
from opentine._graph_types import step_id

#: The step fields an edit may touch; ``model`` is shorthand for ``model_info``.
EDITABLE_ROOTS = ("inputs", "model_info", "tool_info")
_ALIASES = {"model": "model_info"}
_MISSING = object()
#: ``--unset PATH``: the value of an edit that deletes; ``PATH[+]`` appends.
UNSET = object()
APPEND = "[+]"


def add_edit_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--set",
        action="append",
        default=[],
        metavar="PATH=VALUE",
        help="Edit the fork step before forking (inputs.KEY..., model, tool_info.KEY); "
        "VALUE is JSON, else a string; PATH[+]=VALUE appends to a list",
    )
    parser.add_argument(
        "--unset",
        action="append",
        default=[],
        metavar="PATH",
        help="Delete a field or list item of the fork step before forking",
    )
    parser.add_argument(
        "--edit-file", metavar="FILE", help="A JSON object of PATH: VALUE edits for the fork step"
    )


def edit_argv(args: argparse.Namespace) -> list[str]:
    """The edit flags of ``args`` spelled again, for a re-parse (``fork --ref``)."""
    argv = ["--edit-file", args.edit_file] if getattr(args, "edit_file", None) else []
    argv += [f"--set={item}" for item in getattr(args, "set", None) or []]
    return argv + [f"--unset={item}" for item in getattr(args, "unset", None) or []]


def _digest(value: Any) -> str:
    return "" if value is _MISSING else hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _value(text: str) -> Any:
    try:
        return json.loads(text)
    except ValueError:
        return text


def parse_edits(args: argparse.Namespace) -> list[tuple[str, Any]]:
    """The requested edits in order: ``--edit-file``, each ``--set``, each ``--unset``.

    An ``--unset PATH`` is ``(PATH, UNSET)``; an append is a path ending in ``[+]``.
    """
    edits: list[tuple[str, Any]] = []
    if getattr(args, "edit_file", None):
        try:
            data = json.loads(Path(args.edit_file).read_bytes())
        except (OSError, ValueError) as exc:
            raise ValueError(f"--edit-file: cannot read a JSON object: {exc}") from exc
        if not isinstance(data, dict) or not data:
            raise ValueError("--edit-file must hold a non-empty JSON object of PATH: VALUE")
        edits.extend((str(path), value) for path, value in data.items())
    for item in getattr(args, "set", None) or []:
        path, sep, text = item.partition("=")
        if not sep or not path:
            raise ValueError(f"--set expects PATH=VALUE, got {item!r}")
        edits.append((path, _value(text)))
    for path in getattr(args, "unset", None) or []:
        if not path or path.endswith(APPEND):
            raise ValueError(f"--unset expects a field or list item PATH, got {path!r}")
        edits.append((path, UNSET))
    return edits


def _split(path: str) -> tuple[str, list[str]]:
    parts = path.split(".")
    root = _ALIASES.get(parts[0], parts[0])
    if root not in EDITABLE_ROOTS or any(not part for part in parts):
        raise ValueError(
            f"Cannot edit {path!r}: a path starts with inputs, model, model_info or tool_info"
        )
    if root == "model_info" and len(parts) > 1:
        raise ValueError(f"Cannot edit {path!r}: model is a single string")
    return root, parts[1:]


def _index(container: Any, key: str) -> int | None:
    ok = isinstance(container, list) and key.isdigit() and int(key) < len(container)
    return int(key) if ok else None


def _assign(container: Any, keys: list[str], value: Any, path: str) -> Any:
    """Set, append or delete at ``keys`` (dicts and list indexes); return the old value."""
    append = keys[-1].endswith(APPEND)
    if append:
        keys = [*keys[:-1], keys[-1][: -len(APPEND)]] if keys[-1] != APPEND else keys[:-1]
        target = container
        for key in keys[:-1]:
            target = _child(target, key, path)
        if keys:
            index = _index(target, keys[-1])
            has = isinstance(target, dict) and keys[-1] in target
            if not has and index is None:
                raise ValueError(f"Cannot edit {path!r}: no field {keys[-1]!r} to append to")
            target = target[keys[-1]] if has else target[index]
        if not isinstance(target, list):
            raise ValueError(f"Cannot edit {path!r}: [+] appends to a list, not a {_kind(target)}")
        target.append(value)
        return _MISSING
    for key in keys[:-1]:
        container = _child(container, key, path)
    last, index = keys[-1], _index(container, keys[-1])
    if isinstance(container, dict) and (value is not UNSET or last in container):
        old = container.get(last, _MISSING)
        if value is UNSET:
            del container[last]
        else:
            container[last] = value
        return old
    if index is not None:
        old = container[index]
        if value is UNSET:
            del container[index]
        else:
            container[index] = value
        return old
    raise ValueError(f"Cannot edit {path!r}: {last!r} does not name a field or list item")


def _kind(value: Any) -> str:
    return type(value).__name__


def _child(container: Any, key: str, path: str) -> Any:
    if isinstance(container, dict) and isinstance(container.get(key), dict | list):
        return container[key]
    if (index := _index(container, key)) is not None:
        return container[index]
    raise ValueError(f"Cannot edit {path!r}: no field {key!r} to descend into")


def edit_fields(fields: dict[str, Any], edits: list[tuple[str, Any]]) -> list[dict]:
    """Apply ``edits`` in place to ``fields`` (``inputs``/``model_info``/``tool_info``)."""
    changes = []
    for path, value in edits:
        root, keys = _split(path)
        if root == "model_info":
            if not isinstance(value, str) or path.endswith(APPEND):
                raise ValueError("Cannot edit 'model': the value must be a string")
            old, fields[root] = fields[root], value
        else:
            old = _assign(fields[root], keys, value, path) if keys else _root(path)
        new = _MISSING if value is UNSET else value
        change = {"path": path, "old_digest": _digest(old), "new_digest": _digest(new)}
        if value is UNSET or path.endswith(APPEND):  # a plain set keeps its 0.28 record
            change["op"] = "unset" if value is UNSET else "append"
        changes.append(change)
    return changes


def _root(path: str) -> Any:
    raise ValueError(f"Cannot edit {path!r}: name a field inside it")


def edited_step(step: Any, edits: list[tuple[str, Any]]) -> tuple[Any, list[dict]]:
    """A copy of ``step`` with ``edits`` applied, its result cleared, and the change log."""
    fields = {root: copy.deepcopy(getattr(step, root)) for root in EDITABLE_ROOTS}
    changes = edit_fields(fields, edits)
    new_id = step_id(
        step.kind, fields["inputs"], parent_ids=list(step.parent_ids),
        model_info=fields["model_info"], tool_info=fields["tool_info"],
    )  # fmt: skip
    if all(fields[root] == getattr(step, root) for root in EDITABLE_ROOTS):
        raise ValueError("The edit changes nothing: step K already holds these values")
    replacement = dataclasses.replace(
        step, id=new_id, outputs={}, error={}, cost=0.0, usage={}, billing={}, duration=0.0,
        provider="", **fields,
    )  # fmt: skip
    return replacement, changes


def apply_edit(forked: Any, point: str, edits: list[tuple[str, Any]]) -> str:
    """Swap the fork point in ``forked`` for its edited copy; return the new step id."""
    original = forked.graph.steps[point]
    replacement, changes = edited_step(original, edits)
    graph = forked.graph
    del graph.steps[point]
    graph.order.remove(point)
    graph.add(replacement)
    forked.refs = {
        name: replacement.id if ref == point else ref for name, ref in forked.refs.items()
    }
    # The transcript must not keep step K's own entries: they record the call the
    # edit replaced. Unscoped turns (no step_id) carry no step and stay.
    forked.transcript = [item for item in forked.transcript if not _scoped_to(item, point)]
    forked.metadata["edit"] = {
        "step": point,
        "edited_step": replacement.id,
        "changes": changes,
        "executed": False,
    }
    return replacement.id


def _scoped_to(item: Any, point: str) -> bool:
    return isinstance(item, dict) and item.get("step_id") == point


def edit_intent(point: str, edits: list[tuple[str, Any]]) -> dict:
    """What the fork id binds: the point and the digest of every requested edit."""
    return {"edit": {"step": point, "set": [[path, intent_digest(value)] for path, value in edits]}}


def intent_digest(value: Any) -> str:
    """A set's value digest (as 0.28), or ``unset`` -- never a 64-hex digest."""
    return "unset" if value is UNSET else _digest(value)
