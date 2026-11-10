#!/usr/bin/env python3
"""Summarise one nightly stress run (1.0 criterion 5) as JSON and Markdown.

The ``summary`` job of ``.github/workflows/nightly-stress.yml`` downloads every
job's results into one directory and runs::

    python scripts/nightly_summary.py results/ --needs "$NEEDS_JSON" \\
        --out nightly-summary.json --markdown "$GITHUB_STEP_SUMMARY"

``--needs`` is ``toJSON(needs)``: each job's ``result``. The directory holds
JUnit XML (``*.xml``, from ``pytest --junitxml``) and JSON reports (``*.json``,
such as ``coord_scale.py``'s, which carries ``lost``/``duplicated``/
``stale_accepted``). The run is green only when every job succeeded, every
JUnit file has no failure or error, and every coord report counts zero. Exit 1
otherwise, so the summary job itself is red on a red night.
"""

from __future__ import annotations

import argparse
import json
import sys
import xml.etree.ElementTree as ET  # noqa: S405 - our own pytest output
from pathlib import Path
from typing import Any

COORD_ZEROS = ("lost", "duplicated", "stale_accepted")


def junit(path: Path) -> dict[str, Any]:
    root = ET.parse(path).getroot()  # noqa: S314 - our own pytest output
    suites = [root] if root.tag == "testsuite" else list(root.iter("testsuite"))
    keys = ("tests", "failures", "errors", "skipped")
    counts = {k: sum(int(s.get(k, 0)) for s in suites) for k in keys}
    clean = counts["failures"] == 0 and counts["errors"] == 0
    return {**counts, "ok": clean and counts["tests"] > 0}


def report(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text("utf-8"))
    if isinstance(data, dict) and all(k in data for k in COORD_ZEROS):
        return {**{k: data[k] for k in COORD_ZEROS}, "ok": all(data[k] == 0 for k in COORD_ZEROS)}
    return {"ok": bool(data.get("ok", True)) if isinstance(data, dict) else True}


def summarise(results: Path, needs: dict[str, Any]) -> dict[str, Any]:
    jobs = {name: (value or {}).get("result", "unknown") for name, value in sorted(needs.items())}
    files: dict[str, Any] = {}
    for path in sorted(results.rglob("*")) if results.is_dir() else []:
        name = path.relative_to(results).as_posix()
        try:
            if path.suffix == ".xml":
                files[name] = junit(path)
            elif path.suffix == ".json":
                files[name] = report(path)
        except (ET.ParseError, ValueError, OSError) as exc:
            files[name] = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
    ok = bool(jobs) and all(r == "success" for r in jobs.values())
    ok = ok and all(f["ok"] for f in files.values())
    return {"ok": ok, "jobs": jobs, "files": files}


def markdown(summary: dict[str, Any]) -> str:
    title = f"## Nightly stress: {'green' if summary['ok'] else 'RED'}"
    lines = [title, "", "| Job | Result |", "|---|---|"]
    lines += [f"| {name} | {result} |" for name, result in summary["jobs"].items()]
    lines += ["", "| Results file | OK | Detail |", "|---|---|---|"]
    for name, row in summary["files"].items():
        detail = ", ".join(f"{k}={v}" for k, v in row.items() if k != "ok")
        lines.append(f"| {name} | {'yes' if row['ok'] else 'NO'} | {detail} |")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Summarise one nightly stress run.")
    parser.add_argument("results", help="Directory holding the jobs' JUnit XML and JSON reports")
    parser.add_argument("--needs", default="{}", help="toJSON(needs) from the workflow")
    parser.add_argument("--out", help="Write the JSON summary here")
    parser.add_argument("--markdown", help="Append a Markdown table here (GITHUB_STEP_SUMMARY)")
    args = parser.parse_args(argv)
    summary = summarise(Path(args.results), json.loads(args.needs))
    text = json.dumps(summary, indent=2, sort_keys=True)
    print(text)
    if args.out:
        Path(args.out).write_text(text + "\n", "utf-8")
    if args.markdown:
        with open(args.markdown, "a", encoding="utf-8") as handle:
            handle.write(markdown(summary))
    return 0 if summary["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
