"""Fail CI when production modules or the trusted kernel cross release gates."""

from __future__ import annotations

import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "opentine"
MAX_MODULE_LINES = 250
KERNEL = (PACKAGE / "kernel.py",)
BOUNDARIES = {
    "billing": ("models", "remote", "repository", "runtime"),
    "models": ("remote", "repository"),
    "remote": ("models",),
    "repository": ("models", "remote"),
    "trace": ("models", "remote"),
}


def physical_lines(path: Path) -> int:
    return len(path.read_text(encoding="utf-8").splitlines())


def main() -> int:
    errors: list[str] = []
    for path in sorted(PACKAGE.rglob("*.py")):
        lines = physical_lines(path)
        if lines > MAX_MODULE_LINES:
            errors.append(f"{path.relative_to(ROOT)}: {lines} > {MAX_MODULE_LINES} lines")
    kernel_lines = sum(physical_lines(path) for path in KERNEL)
    if kernel_lines > MAX_MODULE_LINES:
        errors.append(f"trusted kernel: {kernel_lines} > {MAX_MODULE_LINES} physical lines")
    for path in KERNEL:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            imported: list[str] = []
            if isinstance(node, ast.ImportFrom):
                imported = [node.module or ""]
            if isinstance(node, ast.Import):
                imported = [name.name for name in node.names]
            for name in imported:
                root = name.split(".", 1)[0]
                if root and root not in sys.stdlib_module_names:
                    errors.append(f"{path.name}:{node.lineno}: kernel dependency {name}")
    for layer, forbidden in BOUNDARIES.items():
        for path in sorted((PACKAGE / layer).rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                names = []
                if isinstance(node, ast.ImportFrom):
                    names = [node.module or ""]
                elif isinstance(node, ast.Import):
                    names = [item.name for item in node.names]
                for name in names:
                    if any(
                        name == f"opentine.{part}" or name.startswith(f"opentine.{part}.")
                        for part in forbidden
                    ):
                        errors.append(
                            f"{path.relative_to(ROOT)}:{node.lineno}: {layer} imports {name}"
                        )
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print(f"architecture gates passed: kernel={kernel_lines} lines, modules<={MAX_MODULE_LINES}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
