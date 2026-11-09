"""The optional tree-sitter backend of ``tine code-graph`` (the ``graph`` extra, 0.48).

:func:`parse` returns ``(symbols, imports)`` for a Python file when
``tree_sitter`` and ``tree_sitter_python`` import, and ``None`` otherwise (no
extra, another language, or a parser error), so the caller falls back to the
regex outline. Only these two packages are ever imported: no grammar is
downloaded or compiled at run time.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Any


@lru_cache(maxsize=1)
def _parser() -> Any:
    try:
        import tree_sitter
        import tree_sitter_python
    except ImportError:
        return None
    try:
        return tree_sitter.Parser(tree_sitter.Language(tree_sitter_python.language()))
    except (TypeError, ValueError, AttributeError):  # an incompatible binding version
        return None


def available() -> bool:
    return _parser() is not None


def _name(node: Any) -> str:
    field = node.child_by_field_name("name")
    return field.text.decode("utf-8", "replace") if field is not None else ""


def parse(raw: bytes, language: str) -> tuple[list[dict[str, Any]], list[str]] | None:
    parser = _parser() if language == "python" else None
    if parser is None:
        return None
    try:
        tree = parser.parse(raw)
    except (ValueError, RuntimeError):
        return None
    symbols: list[dict[str, Any]] = []
    imports: list[str] = []

    def walk(node: Any, parent: str | None, in_class: bool) -> None:
        for child in node.children:
            kind = child.type
            if kind == "decorated_definition":
                walk(child, parent, in_class)
                continue
            if kind in ("class_definition", "function_definition"):
                name = _name(child)
                found = ("class" if kind == "class_definition"
                         else "method" if in_class else "function")  # fmt: skip
                symbols.append({"name": name, "kind": found,
                                "line": child.start_point[0] + 1, "parent": parent})  # fmt: skip
                body = child.child_by_field_name("body")
                if body is not None:
                    walk(body, name, kind == "class_definition")
            elif kind == "import_from_statement":
                module = child.child_by_field_name("module_name")
                if module is not None:
                    imports.append(module.text.decode("utf-8", "replace"))
            elif kind == "import_statement":
                for name in child.children_by_field_name("name"):
                    target = name.child_by_field_name("name") or name
                    imports.append(target.text.decode("utf-8", "replace"))
            elif kind in ("if_statement", "try_statement", "block", "else_clause",
                          "except_clause", "finally_clause", "with_statement"):  # fmt: skip
                walk(child, parent, in_class)

    walk(tree.root_node, None, False)
    return symbols, imports


__all__ = ["available", "parse"]
