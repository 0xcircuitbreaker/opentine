"""Argument parser construction kept independent from command implementations."""

from __future__ import annotations

import argparse

from opentine._canon import FORMAT_VERSION
from opentine._cli_common import HARNESS_FACTORIES
from opentine.pricing_cli import add_pricing_parser
from opentine.remote.server import add_serve_parser
from opentine.repo_cli import add_repo_parsers


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="tine", description="opentine — git for agent runs")
    sub = parser.add_subparsers(dest="command")

    run = sub.add_parser("run", help="Execute a script or harness")
    run.add_argument("script", nargs="?")
    _add_harness_args(run)
    run.add_argument("--save")
    run.add_argument("--autosave")
    run.add_argument("--autosave-interval", type=int, default=0, metavar="N")
    run.add_argument("--autosave-seconds", type=float, default=0.0, metavar="T")

    show = sub.add_parser("show", help="Pretty-print a run tree")
    show.add_argument("run_id")

    verify = sub.add_parser("verify", help="Verify integrity and optionally authenticity")
    verify.add_argument("run_id")
    verify.add_argument("--key-env")
    verify.add_argument("--key-file")
    verify.add_argument("--pubkey")
    verify.add_argument("--require-signature", action="store_true")
    verify.add_argument("--trust-embedded-key", action="store_true")

    sign = sub.add_parser("sign", help="Sign a legacy .tine artifact")
    sign.add_argument("run_id")
    sign.add_argument("--algorithm", choices=("hmac-sha256", "ed25519"), default="hmac-sha256")
    sign.add_argument("--key-env")
    sign.add_argument("--key-file")
    sign.add_argument("--ed25519-key-file")
    sign.add_argument("--key-id")
    sign.add_argument("--signer")
    sign.add_argument("--save")
    # Distinct from --force, which means "sign despite a failed integrity check".
    # One flag cannot mean both, or overwriting a file silently waives tamper detection.
    sign.add_argument(
        "--overwrite", action="store_true", help="Replace an existing --save destination"
    )
    sign.add_argument("--force", action="store_true")

    keygen = sub.add_parser("keygen", help="Generate an Ed25519 keypair")
    keygen.add_argument("--out")
    keygen.add_argument("--pub")
    keygen.add_argument("--force", action="store_true", help="Overwrite an existing key file")

    migrate = sub.add_parser("migrate", help="Upgrade a legacy .tine file")
    migrate.add_argument("run_id")
    migrate.add_argument("--to", type=int, default=None, help=f"Target version ({FORMAT_VERSION})")
    migrate.add_argument("--dry-run", action="store_true")
    migrate.add_argument("--in-place", action="store_true")
    migrate.add_argument("--save")
    migrate.add_argument("--force", action="store_true")

    listing = sub.add_parser("ls", help="List recent legacy runs")
    _add_filter_args(listing)
    listing.add_argument("--limit", type=int, default=20)

    search = sub.add_parser("search", help="Search legacy runs")
    search.add_argument("query", nargs="*")

    tag = sub.add_parser("tag", help="Add, remove, or list tags")
    tag.add_argument("run_id")
    tag.add_argument("--add", action="append", default=[])
    tag.add_argument("--remove", action="append", default=[])
    tag.add_argument("--list", action="store_true")

    sub.add_parser("reindex", help="Rebuild the legacy run index")
    cost = sub.add_parser("cost", help="Show cost and budget state")
    cost.add_argument("run_id")

    fork = sub.add_parser("fork", help="Fork a legacy run")
    fork.add_argument("run_id")
    fork.add_argument("--from-step", required=True)
    fork.add_argument("--save")
    fork.add_argument("--force", action="store_true")
    _add_harness_args(fork)

    replay = sub.add_parser("replay", help="Replay a run")
    replay.add_argument("run_id")
    replay.add_argument("--from-step")
    replay.add_argument("--mode", choices=("cache", "rerun"), default="cache")
    replay.add_argument("--inspect", action="store_true")
    replay.add_argument("--dry-run", action="store_true")
    replay.add_argument("--save")
    replay.add_argument("--force", action="store_true")
    replay.add_argument("--compare", action="store_true")
    _add_harness_args(replay)

    diff = sub.add_parser("diff", help="Diff two legacy runs")
    diff.add_argument("run_a")
    diff.add_argument("run_b")
    resume = sub.add_parser("resume", help="Resume a paused run")
    resume.add_argument("run_id")

    add_pricing_parser(sub)
    add_serve_parser(sub)
    add_repo_parsers(sub)
    return parser


def _add_filter_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--tag", action="append", default=[])
    parser.add_argument("--model")
    parser.add_argument("--status")
    parser.add_argument("--cost-min", type=float)
    parser.add_argument("--cost-max", type=float)
    parser.add_argument("--since")
    parser.add_argument("--until")
    parser.add_argument("--grep", action="append", default=[])


def _add_harness_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--harness", choices=sorted(HARNESS_FACTORIES))
    parser.add_argument("--prompt")
    parser.add_argument("--cwd")
    parser.add_argument("--harness-command")
    parser.add_argument("--harness-arg", action="append", default=[])
    parser.add_argument("--harness-login-env", action="store_true")
    parser.add_argument("--harness-env", action="append", default=[])
    parser.add_argument("--harness-timeout", type=float, default=3_600.0, metavar="SECONDS")
    parser.add_argument("--harness-max-output", type=int, default=4_000_000, metavar="CHARS")
    parser.add_argument("--harness-max-events", type=int, default=10_000, metavar="N")
    parser.add_argument("--harness-max-line-bytes", type=int, default=1_000_000, metavar="BYTES")
