"""Global ``tine`` flags applied before any command runs: ``--no-compress``, ``--fips``."""

from __future__ import annotations

import argparse
import contextlib
import os
from collections.abc import Iterator

from opentine import _fips


def add_global_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--no-compress",
        action="store_true",
        help="Write plain .tine files and repositories that releases before 0.11 can read",
    )
    parser.add_argument(
        "--fips",
        action="store_true",
        help=f"FIPS mode: require the OpenSSL FIPS provider, refuse other primitives ({_fips.ENV})",
    )


def apply_global_flags(args: argparse.Namespace) -> None:
    if getattr(args, "no_compress", False):
        os.environ["OPENTINE_COMPRESS"] = "0"
    if getattr(args, "fips", False):
        os.environ[_fips.ENV] = "1"
    with fips_errors():
        _fips.require_provider()


@contextlib.contextmanager
def fips_errors() -> Iterator[None]:
    """A FIPS refusal is exit 6 (``trust_required``: unsupported here)."""
    from opentine._cli_errors import TRUST_REQUIRED, fail

    try:
        yield
    except _fips.FipsError as exc:
        fail(str(exc), TRUST_REQUIRED, cause=exc)
