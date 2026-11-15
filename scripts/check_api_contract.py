"""Report a hosted backend's ``/api/*`` routes that docs/api/openapi-v1.yaml does not document.

Tineyard (the hosted web app) serves its backend under ``/api/*`` and maps it
onto the v1 API (web rule 4: whatever it serves, ``tine serve`` serves too).
Give this script a route dump from a staging deployment and it lists every
``/api/*`` route with no documented operation::

    python scripts/check_api_contract.py routes.txt

The file holds one ``METHOD /api/path`` per line (``#`` comments and blank
lines are skipped), or a JSON array of ``{"method": ..., "path": ...}``.
Path parameters may be written ``{name}``, ``:name`` or ``[name]``; only
their position matters. ``/api/X`` is documented when the spec has the same
method on ``/v1/X`` (``--map`` changes the prefixes). Routes outside the
prefix are ignored. Exit status: 0 when every route is documented, 1 when
some are not, 2 when the file cannot be read.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

_PARAM = re.compile(r"\{[^/{}]+\}|:[A-Za-z_][A-Za-z0-9_]*|\[[^/\[\]]+\]")
_METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}


def shape(path: str) -> str:
    """*path* with every parameter as ``{}`` and no trailing slash."""
    return _PARAM.sub("{}", path.split("?", 1)[0]).rstrip("/") or "/"


def read_routes(text: str) -> list[tuple[str, str]]:
    stripped = text.lstrip()
    if stripped.startswith("["):
        rows = json.loads(stripped)
        return [(str(row["method"]).upper(), str(row["path"])) for row in rows]
    routes = []
    for number, line in enumerate(text.splitlines(), 1):
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) != 2 or parts[0].upper() not in _METHODS:
            raise ValueError(f"line {number}: expected 'METHOD /path', got {line!r}")
        routes.append((parts[0].upper(), parts[1]))
    return routes


def documented() -> set[tuple[str, str]]:
    from opentine.remote._openapi import build

    return {
        (method.upper(), shape(path))
        for path, operations in build()["paths"].items()
        for method in operations
    }


def undocumented(
    routes: list[tuple[str, str]], spec: set[tuple[str, str]], *, source="/api", target="/v1"
) -> list[tuple[str, str]]:
    missing = set()
    for method, path in routes:
        if path != source and not path.startswith(source.rstrip("/") + "/"):
            continue
        mapped = target + path[len(source.rstrip("/")) :]
        if method == "HEAD" and ("GET", shape(mapped)) in spec:
            continue
        if (method, shape(mapped)) not in spec:
            missing.add((method, path))
    return sorted(missing, key=lambda row: (row[1], row[0]))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("routes", type=Path, help="Route dump: 'METHOD /api/path' lines or JSON")
    parser.add_argument(
        "--map",
        default="/api=/v1",
        metavar="SRC=DST",
        help="Prefix mapping from the dump onto the spec (default /api=/v1)",
    )
    args = parser.parse_args(argv)
    source, _, target = args.map.partition("=")
    if not source.startswith("/") or not target.startswith("/"):
        parser.error("--map takes /SOURCE=/TARGET")
    try:
        routes = read_routes(args.routes.read_text(encoding="utf-8"))
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"check_api_contract: cannot read {args.routes}: {exc}", file=sys.stderr)
        return 2
    missing = undocumented(routes, documented(), source=source, target=target)
    for method, path in missing:
        print(f"undocumented: {method} {path}")
    checked = sum(1 for _, path in routes if path.startswith(source))
    print(f"{checked} {source} routes checked, {len(missing)} undocumented")
    return 1 if missing else 0


if __name__ == "__main__":
    raise SystemExit(main())
