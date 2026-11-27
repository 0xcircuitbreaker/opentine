"""The introspection lint (0.85): ``tine eval lint FILE...``.

An AST pass over candidate (or scorer) Python source that flags code reaching
for the evaluator instead of the task:

* ``advisory:introspection.stack`` -- ``sys._getframe``, ``inspect`` frame and
  stack calls, ``traceback`` stack walks, frame attributes (``f_back``,
  ``f_locals``, ``f_globals``, ``tb_frame``, ``gi_frame``, ``cr_frame``),
  ``sys.settrace`` / ``sys.setprofile``;
* ``advisory:introspection.gc`` -- ``gc.get_referrers``, ``gc.get_objects``,
  ``gc.get_referents``;
* ``advisory:introspection.dynamic`` -- ``eval``, ``exec``, ``compile``,
  ``__import__``, ``importlib.import_module``, and ``getattr`` with a name that
  is not a string literal;
* ``advisory:introspection.grader-read`` -- a string literal naming a grader
  path (``--grader``), a test file (``test_*.py``, ``*_test.py``,
  ``conftest.py``) or a ``tests/`` directory.

The lint is evadable (names built at runtime), so its findings are advisory and
never block by default (owner decision D12); ``--strict`` exits 1 on any.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Any

_STACK_CALLS = {("sys", "_getframe"), ("sys", "_current_frames"), ("sys", "settrace"),
                ("sys", "setprofile"), ("inspect", "currentframe"), ("inspect", "stack"),
                ("inspect", "getouterframes"), ("inspect", "getinnerframes"),
                ("inspect", "trace"), ("inspect", "getframeinfo"),
                ("traceback", "extract_stack"), ("traceback", "walk_stack"),
                ("traceback", "print_stack"), ("traceback", "format_stack")}  # fmt: skip
_GC_CALLS = {("gc", "get_referrers"), ("gc", "get_objects"), ("gc", "get_referents")}
_DYNAMIC = {"eval", "exec", "compile", "__import__"}
_FRAME_ATTRS = {"f_back", "f_locals", "f_globals", "f_code", "tb_frame", "gi_frame", "cr_frame",
                "ag_frame"}  # fmt: skip
_TEST_NAME = re.compile(r"(^|[\\/])(test_[^\\/]*\.py|[^\\/]*_test\.py|conftest\.py|tests[\\/])")


def _dotted(node: ast.AST) -> tuple[str, ...]:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return tuple(reversed(parts))
    return ()


def _finding(path: str, node: ast.AST, kind: str, detail: str) -> dict[str, Any]:
    return {"file": path, "line": getattr(node, "lineno", 0),
            "code": f"advisory:introspection.{kind}", "detail": detail}  # fmt: skip


def lint_source(text: str, path: str, graders: list[str]) -> list[dict[str, Any]]:
    """Findings for one module's source; a syntax error is itself a finding."""
    try:
        tree = ast.parse(text, filename=path)
    except SyntaxError as exc:
        return [{"file": path, "line": exc.lineno or 0, "code": "advisory:introspection.unparsed",
                 "detail": f"not Python the lint can read: {exc.msg}"}]  # fmt: skip
    names = [Path(g).name for g in graders]
    out: list[dict[str, Any]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = _dotted(node.func)
            tail = name[-2:] if len(name) >= 2 else ()
            if tail in _STACK_CALLS:
                out.append(_finding(path, node, "stack", ".".join(name)))
            elif tail in _GC_CALLS:
                out.append(_finding(path, node, "gc", ".".join(name)))
            elif name in {(n,) for n in _DYNAMIC} or tail == ("importlib", "import_module"):
                out.append(_finding(path, node, "dynamic", ".".join(name)))
            elif name == ("getattr",) and len(node.args) >= 2 and not (
                isinstance(node.args[1], ast.Constant) and isinstance(node.args[1].value, str)
            ):  # fmt: skip
                out.append(_finding(path, node, "dynamic", "getattr with a computed name"))
        elif isinstance(node, ast.Attribute) and node.attr in _FRAME_ATTRS:
            out.append(_finding(path, node, "stack", f"frame attribute {node.attr}"))
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            value = node.value
            if _TEST_NAME.search(value) or any(n and n in value for n in names):
                out.append(_finding(path, node, "grader-read", f"names {value[:80]!r}"))
    return sorted(out, key=lambda f: (f["line"], f["code"], f["detail"]))


def lint(files: list[Path], graders: list[Path] | None = None) -> dict[str, Any]:
    """``{files, findings}`` over *files*; grader paths are matched by file name."""
    grader_names = [p.as_posix() for p in graders or []]
    findings: list[dict[str, Any]] = []
    for path in files:
        text = Path(path).read_bytes().decode("utf-8", "replace")
        findings += lint_source(text, Path(path).as_posix(), grader_names)
    return {"files": len(files), "findings": findings}


__all__ = ["lint", "lint_source"]
