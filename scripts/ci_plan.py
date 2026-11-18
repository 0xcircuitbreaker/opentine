#!/usr/bin/env python3
"""Plan one CI run: which Python test cells run, and whether the Python matrix runs at all.

    python scripts/ci_plan.py --event pull_request --changed changed.txt
    python scripts/ci_plan.py --event push

Writes ``name=value`` lines to ``$GITHUB_OUTPUT`` (or stdout when it is unset):

* ``python``: ``false`` only for a pull request that changes nothing but prose
  (Markdown under ``docs/``, or at the repository root): the Python matrix is skipped;
* ``matrix``: the test matrix as ``{"include": [...]}``. Push to main, schedule and
  workflow_dispatch get the full 3 OS x 4 Python matrix; a pull request gets the slim
  matrix, or a single Linux cell when it changes only TypeScript/IDE sources and
  prose (many Python tests read ts/ and ide/ files, so they still run once). Every
  Windows cell is split into ``WINDOWS_SHARDS`` jobs so no single Windows job runs
  the whole suite.

A missing or unreadable changed-file list means "run everything": the plan only ever
skips work it can prove is irrelevant.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

PYTHONS = ("3.11", "3.12", "3.13", "3.14")
OSES = ("ubuntu-latest", "macos-latest", "windows-latest")
WINDOWS_SHARDS = 4
#: The pull-request matrix: both ends of the supported range on Linux, one
#: Windows and one macOS cell. Main and the nightly run keep the full matrix.
PR_CELLS = (
    ("ubuntu-latest", "3.11"),
    ("ubuntu-latest", "3.14"),
    ("windows-latest", "3.12"),
    ("macos-latest", "3.13"),
)
#: The one cell a TypeScript-only pull request runs.
TS_ONLY_CELLS = (("ubuntu-latest", "3.14"),)
#: TypeScript and IDE sources.
TS_PREFIXES = ("ts/", "ide/")
#: Markdown under these prefixes is prose only. Markdown elsewhere (for example
#: tests/ or opentine/) may be test data, so it does not count as docs-only.
DOC_PREFIXES = ("docs/", ".github/ISSUE_TEMPLATE/")


def is_docs(path: str) -> bool:
    """True for prose: Markdown at the root or under a docs prefix."""
    return path.endswith(".md") and ("/" not in path or path.startswith(DOC_PREFIXES))


def is_ts(path: str) -> bool:
    return path.startswith(TS_PREFIXES)


def scope(event: str, changed: list[str] | None) -> str:
    """``docs``, ``ts`` or ``full``: how much of the Python matrix this run needs."""
    if event != "pull_request" or not changed:
        return "full"
    if all(is_docs(path) for path in changed):
        return "docs"
    if all(is_docs(path) or is_ts(path) for path in changed):
        return "ts"
    return "full"


def _cell(os_name: str, python: str, shard: int, shards: int) -> dict:
    return {"os": os_name, "python-version": python, "shard": shard, "shards": shards}


def matrix(event: str, kind: str = "full") -> dict:
    if event == "pull_request" and kind == "ts":
        cells = list(TS_ONLY_CELLS)
    elif event == "pull_request":
        cells = list(PR_CELLS)
    else:
        cells = [(os_name, python) for os_name in OSES for python in PYTHONS]
    include = []
    for os_name, python in cells:
        shards = WINDOWS_SHARDS if os_name == "windows-latest" else 1
        include.extend(_cell(os_name, python, k, shards) for k in range(1, shards + 1))
    return {"include": include}


def read_changed(path: str | None) -> list[str] | None:
    if not path:
        return None
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError:
        return None
    return [line.strip() for line in text.splitlines() if line.strip()]


def plan(event: str, changed: list[str] | None) -> dict[str, str]:
    kind = scope(event, changed)
    return {
        "python": "false" if kind == "docs" else "true",
        "matrix": json.dumps(matrix(event, kind), separators=(",", ":")),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--event", required=True, help="github.event_name")
    parser.add_argument("--changed", help="file with one changed path per line")
    args = parser.parse_args(argv)
    lines = [f"{k}={v}" for k, v in plan(args.event, read_changed(args.changed)).items()]
    target = os.environ.get("GITHUB_OUTPUT")
    if target:
        with open(target, "a", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")
    else:
        sys.stdout.write("\n".join(lines) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
