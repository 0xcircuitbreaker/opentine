"""Build ``tine-verify.pyz``, the stdlib-only offline verifier, reproducibly.

    python scripts/build_verifier.py [--out dist] [--check]

The archive is a pure function of the sources and ``SOURCE_DATE_EPOCH`` (see
``opentine/_pyz_build.py``). ``--check`` builds it twice and fails unless the
two builds are byte-identical. The builder module is loaded from its file, so
this script needs neither opentine installed nor any of its dependencies.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _builder():
    spec = importlib.util.spec_from_file_location(
        "_tine_pyz_build", ROOT / "opentine" / "_pyz_build.py"
    )
    if spec is None or spec.loader is None:
        raise SystemExit("cannot load opentine/_pyz_build.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--out", default="dist", help="output directory (default: dist)")
    parser.add_argument("--check", action="store_true", help="build twice and compare bytes")
    args = parser.parse_args(argv)
    builder = _builder()
    first = builder.build_bytes()
    if args.check and builder.build_bytes() != first:
        print("tine-verify.pyz is not reproducible: two builds differ", file=sys.stderr)
        return 1
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    target = out / builder.NAME
    target.write_bytes(first)
    print(f"{hashlib.sha256(first).hexdigest()}  {target.as_posix()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
