"""Every ``from opentine... import name`` in scripts/ and benches/ must resolve.

Bench and bake-off jobs only run on main, and ruff cannot see that an imported
name was renamed (0.86.1 renamed ``_pack_sizes``; the bake-off broke on main).
This walks each file's AST, including function-local imports, and checks the
names exist on the imported module, without executing the scripts.
"""

from __future__ import annotations

import ast
import importlib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
DIRS = ("scripts", "benches", "benchmarks")


def _imports() -> list[tuple[str, int, str, str]]:
    found = []
    for d in DIRS:
        for path in sorted((ROOT / d).rglob("*.py")) if (ROOT / d).is_dir() else []:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.level == 0:
                    mod = node.module or ""
                    if mod == "opentine" or mod.startswith("opentine."):
                        for alias in node.names:
                            rel = str(path.relative_to(ROOT))
                            found.append((rel, node.lineno, mod, alias.name))
    return found


IMPORTS = _imports()


def test_scripts_import_opentine() -> None:
    assert IMPORTS, "expected scripts to import opentine"


@pytest.mark.parametrize(("path", "line", "module", "name"), IMPORTS)
def test_imported_name_exists(path: str, line: int, module: str, name: str) -> None:
    mod = importlib.import_module(module)
    if name == "*" or hasattr(mod, name):
        return
    importlib.import_module(f"{module}.{name}")  # submodule import, else fails
