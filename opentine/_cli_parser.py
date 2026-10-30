"""Argument parser construction kept independent from command implementations."""

from __future__ import annotations

import argparse

from opentine._canon import FORMAT_VERSION
from opentine._cli_bisect import add_bisect_parser
from opentine._cli_export import add_export_parser
from opentine._cli_fleet import add_fleet_parser
from opentine._cli_gitlink import add_gitlink_parsers
from opentine._cli_harnesses import _add_harness_args, add_harnesses_parser
from opentine._cli_help import finish_parser
from opentine._cli_hook import add_hook_parser
from opentine._cli_import import add_import_parser
from opentine._cli_intoto import add_attestation_verify_args
from opentine._cli_json_flow import STATS_SCOPE_NOTE
from opentine._cli_keygen import add_keygen_parser
from opentine._cli_media import add_media_parser
from opentine._cli_plugin import add_plugin_parser
from opentine._cli_run_model import add_model_args
from opentine._cli_stats import GROUP_BY_CHOICES
from opentine._cli_storage import add_storage_parsers
from opentine._cli_unify import add_unify_args
from opentine._cli_who import add_actions_parsers
from opentine._repo_cli_parser import add_repo_parsers
from opentine._version import __version__
from opentine.pricing_cli import add_pricing_parser
from opentine.remote.server import add_serve_parser


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="tine", description="opentine — git for agent runs")
    parser.add_argument("-V", "--version", action="version", version=f"opentine {__version__}")
    parser.add_argument(
        "--no-compress",
        action="store_true",
        help="Write plain .tine files and repositories that releases before 0.11 can read",
    )
    sub = parser.add_subparsers(dest="command")

    run = sub.add_parser("run", help="Execute a script, a harness, or a bundled model")
    run.add_argument("script", nargs="?")
    _add_harness_args(run)
    # The third run mode, and the only one that needs nothing written first: it
    # calls a bundled adapter directly, so it is exclusive with the other two.
    add_model_args(run)
    # --save works in both modes; the autosave trio checkpoints a run in flight
    # and so needs --harness. Script mode refuses them rather than ignoring them.
    run.add_argument(
        "--save", metavar="PATH", help="Write the run here instead of .tine_runs/<id>.tine"
    )
    # Same meaning as everywhere else a verb writes an artifact: replace what is
    # already at the --save destination. Without it the second run refuses.
    run.add_argument("--force", action="store_true", help="Replace an existing --save destination")
    run.add_argument("--autosave", metavar="PATH", help="Checkpoint path (--harness runs only)")
    run.add_argument(
        "--autosave-interval",
        type=int,
        default=0,
        metavar="N",
        help="Checkpoint every N steps (--harness runs only)",
    )
    run.add_argument(
        "--autosave-seconds",
        type=float,
        default=0.0,
        metavar="T",
        help="Checkpoint every T seconds (--harness runs only)",
    )

    show = sub.add_parser("show", help="Pretty-print a run tree")
    show.add_argument("run_id")

    verify = sub.add_parser("verify", help="Verify integrity and optionally authenticity")
    verify.add_argument("run_id")
    verify.add_argument("--key-env", help="Environment variable holding the HMAC key")
    verify.add_argument("--key-file", help="File holding the HMAC key (never a public key)")
    verify.add_argument("--pubkey", help="File holding a trusted Ed25519 public key")
    verify.add_argument("--require-signature", action="store_true")
    verify.add_argument("--trust-embedded-key", action="store_true")
    verify.add_argument(
        "--pin",
        action="append",
        metavar="FINGERPRINT",
        help="Trust the embedded Ed25519 key only if its sha256 fingerprint is this (repeatable)",
    )

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

    add_keygen_parser(sub)

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

    # Same filter set as `ls`, so a filter learned there aggregates here unchanged.
    stats = sub.add_parser(
        "stats",
        help=f"Aggregate legacy runs — {STATS_SCOPE_NOTE}",
        description=f"Aggregate runs across the file index — {STATS_SCOPE_NOTE}",
    )
    _add_filter_args(stats)
    stats.add_argument("--group-by", choices=GROUP_BY_CHOICES, default=None)
    stats.add_argument(
        "--deep",
        action="store_true",
        help="Load each matched run for tokens and duration, which the index does not store",
    )
    stats.add_argument("--limit", type=int, default=20, help="Max groups to show; 0 for all")

    tag = sub.add_parser("tag", help="Tag a v3 run (tags/NAME), or edit a legacy run's labels")
    tag.add_argument("run_id", nargs="?", metavar="NAME_OR_RUN")
    tag.add_argument("--add", action="append", default=[])
    tag.add_argument("--remove", action="append", default=[])
    tag.add_argument("--list", action="store_true")

    sub.add_parser("reindex", help="Rebuild the legacy run index")
    cost = sub.add_parser("cost", help="Show cost and budget state")
    cost.add_argument("run_id")

    # The other half of the cost story, and deliberately a separate verb: `cost`
    # sums the price each step RECORDED at capture, `price` recomputes it from
    # the catalog, so an imported or uncosted run is priced at all and any run
    # can be re-priced under a corrected or past catalog. Read-only, both ways.
    price = sub.add_parser(
        "price",
        help="Re-price a run from the pricing catalog (tine cost sums recorded cost)",
        description=(
            "Recompute a run's cost post-hoc from its recorded (provider, model, usage) "
            "against the pricing catalog, and report it without writing anything. "
            "Distinct from `tine cost`, which sums the cost recorded at capture: this "
            "prices imported and uncosted runs too, and a step no rate card covers is "
            "reported unknown rather than as free."
        ),
    )
    price.add_argument("run_id")
    price.add_argument(
        "--at",
        metavar="DATE",
        default=None,
        help="Price against the catalog effective on this ISO date (default: today)",
    )

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
    # --verify replays into a temp workspace; it writes only when --save names one.
    replay.add_argument(
        "--verify",
        action="store_true",
        help="Check the replay reproduces the run: exit 0 reproduced, 1 drift",
    )
    replay.add_argument(
        "--ignore-cost-drift",
        action="store_true",
        help="With --verify, let cost/usage/billing drift alone still pass",
    )
    _add_harness_args(replay)

    diff = sub.add_parser("diff", help="Diff two legacy runs")
    diff.add_argument("run_a")
    diff.add_argument("run_b")
    # Same flag, same meaning as `repo-diff --exit-code`: one habit for both formats.
    diff.add_argument(
        "--exit-code",
        action="store_true",
        help="Exit 1 when the runs differ and 0 when they are identical, like git diff",
    )
    resume = sub.add_parser("resume", help="Resume a paused run")
    resume.add_argument("run_id")

    importer = add_import_parser(sub)
    add_export_parser(sub)
    add_attestation_verify_args(verify)

    # --json is purely additive (not on `export`, whose output is the document itself).
    # `replay` earns it only through --verify, whose verdict is a result a script
    # reads; a plain replay's output is the artifact it writes. `import` writes an
    # artifact too, but its result is the run id a caller must then address, and
    # `tag` earns it on its listing mode alone (see cmd_tag).
    readable = (show, verify, listing, search, stats, cost, price, replay, diff, importer, tag)
    for command in readable:
        command.add_argument(
            "--json", action="store_true", help="Emit a machine-readable JSON object instead"
        )

    add_pricing_parser(sub)
    add_serve_parser(sub)
    add_harnesses_parser(sub)
    add_storage_parsers(sub)
    add_actions_parsers(sub)
    add_gitlink_parsers(sub)
    add_bisect_parser(sub)
    add_media_parser(sub)
    add_hook_parser(sub)
    add_plugin_parser(sub)
    add_fleet_parser(sub)
    add_repo_parsers(sub)
    add_unify_args(sub)
    return finish_parser(parser)


def _add_filter_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--tag", action="append", default=[])
    parser.add_argument("--model")
    parser.add_argument("--status")
    parser.add_argument("--cost-min", type=float)
    parser.add_argument("--cost-max", type=float)
    parser.add_argument("--since")
    parser.add_argument("--until")
    parser.add_argument("--grep", action="append", default=[])
