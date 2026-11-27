"""AST-level diff of two Python sources (0.88), for ``tine lineage diff``.

Each source becomes a map of *symbols*: every function and class by qualified
name (``Class.method``, ``outer.<locals>.inner`` is folded into its parent), a
class's own header (bases, keywords, decorators and the statements that are not
definitions) as ``Class:header``, and every other module statement by the
digest of its dump. Two symbols are equal only when their ``ast.dump`` is, so a
changed default, decorator, constant or operator is a change while comments,
blank lines and formatting are not. A source that does not parse is diffed by
tokens instead (:mod:`opentine._sdiff_text`).
"""

from __future__ import annotations

import ast
import hashlib
from typing import Any

_DEFS = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
MAX_SOURCE = 8 << 20  # bytes: a larger source is diffed by tokens


def _dump(node: ast.AST) -> str:
    return ast.dump(node, include_attributes=False)


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def _walk(body: list[ast.stmt], prefix: str, out: dict[str, str], order: list[str]) -> None:
    for node in body:
        if isinstance(node, ast.ClassDef):
            name = f"{prefix}{node.name}"
            header = ast.ClassDef(
                name=node.name, bases=node.bases, keywords=node.keywords,
                decorator_list=node.decorator_list,
                body=[n for n in node.body if not isinstance(n, _DEFS)],
                type_params=getattr(node, "type_params", []),
            )  # fmt: skip
            _put(out, order, f"{name}:header", _dump(header))
            _walk([n for n in node.body if isinstance(n, _DEFS)], f"{name}.", out, order)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            _put(out, order, f"{prefix}{node.name}", _dump(node))
        else:
            text = _dump(node)
            _put(out, order, f"{prefix}<{type(node).__name__.lower()} {_digest(text)}>", text)


def _put(out: dict[str, str], order: list[str], name: str, text: str) -> None:
    if name in out:  # a redefinition: both definitions count, in order
        index = 2
        while f"{name}#{index}" in out:
            index += 1
        name = f"{name}#{index}"
    out[name] = text
    order.append(name)


def symbols(source: str) -> tuple[dict[str, str], list[str]] | None:
    """``({qualified name: dump}, order)``, or ``None`` when *source* does not parse."""
    if len(source) > MAX_SOURCE:
        return None
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return None
    out: dict[str, str] = {}
    order: list[str] = []
    try:
        _walk(tree.body, "", out, order)
    except RecursionError:
        return None
    return out, order


def diff(before: str, after: str) -> dict[str, Any] | None:
    """``{"structural", "changes"}`` over symbols; ``None`` when either side fails to parse."""
    from opentine._sdiff_text import shown

    old, new = symbols(before), symbols(after)
    if old is None or new is None:
        return None
    (a, a_order), (b, b_order) = old, new
    changes = []
    for name in sorted(set(a) | set(b)):
        if name not in b:
            changes.append({"op": "removed", "item": shown(name, 200)})
        elif name not in a:
            changes.append({"op": "added", "item": shown(name, 200)})
        elif a[name] != b[name]:
            changes.append({"op": "changed", "item": shown(name, 200)})
    if [n for n in a_order if n in b] != [n for n in b_order if n in a]:
        changes.append({"op": "reordered", "item": "definitions"})
    return {"structural": bool(changes), "changes": changes}


__all__ = ["diff", "symbols"]
