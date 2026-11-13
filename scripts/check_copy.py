"""Overclaim lint for documentation copy (0.51, ROADMAP §12 "Copy discipline").

Fails on any banned phrase, case-insensitively, in ``README.md`` and every
``docs/**/*.md``. The phrases claim more than a signature or a verifier can
show. Files that quote the rule itself are exempt by name in ``ALLOWED`` (the
root ``CHANGELOG.md`` is history and is not scanned at all).

    python scripts/check_copy.py          # exit 1 and list every hit

Offline, standard library only.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

BANNED = (
    "verified execution",
    "genuine model output",
    "only line-level attribution",
    "unique line-level attribution",
    "proves the model",
)

#: Files that quote the banned list to state the rule (repo-relative, POSIX).
ALLOWED = frozenset({"docs/ROADMAP.md"})

_PATTERN = re.compile(
    "|".join(r"\s+".join(map(re.escape, phrase.split())) for phrase in BANNED), re.IGNORECASE
)


def targets(root: Path = ROOT) -> list[Path]:
    """README.md and docs/**/*.md, minus the allow-list, in a stable order."""
    found = [root / "README.md", *sorted((root / "docs").rglob("*.md"))]
    return [p for p in found if p.is_file() and p.relative_to(root).as_posix() not in ALLOWED]


def hits(root: Path = ROOT) -> list[tuple[str, int, str]]:
    """``(path, line, phrase)`` for every banned phrase found."""
    out = []
    for path in targets(root):
        text = path.read_text("utf-8")
        for match in _PATTERN.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            out.append((path.relative_to(root).as_posix(), line, " ".join(match.group().split())))
    return out


def main(argv: list[str] | None = None) -> int:
    found = hits()
    for path, line, phrase in found:
        print(f"{path}:{line}: banned phrase {phrase!r} (see ROADMAP §12, copy discipline)")
    if found:
        return 1
    print(f"copy lint: {len(targets())} files clean")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
