"""``tine trends [--json] [--export FILE]`` (0.72): capability trends over lineage generations.

Reads the 0.58 lineage folder and the records it cites
(:mod:`opentine._trends_collect`), computes per-variant and per-generation
metrics with intervals (:mod:`opentine._trends`) and prints them. ``--export``
writes the inputs and the reported numbers as one canonical JSON file that
``opentine/data/trends/recompute.mjs`` (a browser or Node) and
:func:`opentine._trends.compute` recompute byte for byte.

``--sign-lengths FILE --key KEY --suite NAME`` signs a ``{item: minutes}`` map
as ``opentine.trends.task-lengths/1`` (:mod:`opentine._trends_lengths`) and
writes it to ``--task-lengths`` (default ``REPO/.tine/trends/task-lengths.json``).
See docs/TRENDS.md.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections.abc import Callable
from pathlib import Path

from opentine._cli_common import _terminal, console
from opentine._cli_errors import USAGE, error
from opentine._lineage import MAX_BYTES, MAX_FILES

SCHEMA = "tine-cli-trends/1"


def add_trends_parser(subparsers: argparse._SubParsersAction) -> None:
    from opentine._eval_stats import DEFAULT_RESAMPLES

    p = subparsers.add_parser("trends", help="Capability trends over lineage generations")
    p.add_argument("--repo", default=".", metavar="PATH", help="v3 repository")
    p.add_argument("--dir", metavar="DIR", help="Lineage folder (REPO/.tine/lineage)")
    p.add_argument("--loop", metavar="LOOP", help="Only this loop's variants")
    p.add_argument("--json", action="store_true", help="Machine-readable output")
    p.add_argument("--export", metavar="FILE", help="Write the recomputable export here")
    p.add_argument("--task-lengths", metavar="FILE",
                   help="Signed task lengths (REPO/.tine/trends/task-lengths.json)")  # fmt: skip
    p.add_argument("--alpha", default="0.05", help="Interval level (default 0.05)")
    p.add_argument("--seed", type=int, default=0, help="Resampling seed (0..2^53-1)")
    p.add_argument("--resamples", type=int, default=DEFAULT_RESAMPLES, metavar="N",
                   help=f"Bootstrap resamples (default {DEFAULT_RESAMPLES})")  # fmt: skip
    p.add_argument("--promotion-policy", metavar="TOML",
                   help="Also pin eval signers to this policy's eval_signers")  # fmt: skip
    p.add_argument("--fail-on-regression", action="store_true",
                   help="Exit 1 when a variant regresses against a parent")  # fmt: skip
    p.add_argument("--max-files", type=int, default=MAX_FILES, metavar="N",
                   help=f"Refuse a lineage folder over N files ({MAX_FILES})")  # fmt: skip
    p.add_argument("--max-bytes", type=int, default=MAX_BYTES, metavar="N",
                   help=f"Refuse a lineage folder over N bytes ({MAX_BYTES})")  # fmt: skip
    p.add_argument("--sign-lengths", metavar="FILE",
                   help="Sign this {item: minutes} JSON as task lengths and exit")  # fmt: skip
    p.add_argument("--key", metavar="KEY", help="Ed25519 key for --sign-lengths")
    p.add_argument("--suite", default="default", help="Suite name for --sign-lengths")
    p.add_argument("--at", metavar="TIME", help="YYYY-MM-DDTHH:MM:SSZ (default: now)")


def _lengths_path(args: argparse.Namespace) -> Path:
    from opentine._trends_lengths import DEFAULT

    return Path(args.task_lengths) if args.task_lengths else Path(args.repo) / DEFAULT


def _sign(args: argparse.Namespace) -> dict:
    from opentine._promote import _now
    from opentine._signing_keys import ed25519_private_from_file
    from opentine._trends_lengths import sign

    if not args.key:
        raise error("trends --sign-lengths needs --key", USAGE, prefix="trends: ")
    lengths = json.loads(Path(args.sign_lengths).read_bytes().decode("utf-8"))
    record = sign(lengths, ed25519_private_from_file(args.key, signer=False), suite=args.suite,
                  at=args.at or _now())  # fmt: skip
    path = _lengths_path(args)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes((json.dumps(record, indent=2, sort_keys=True) + "\n").encode("utf-8"))
    return {"signed": path.as_posix(), "suite": record["suite"], "signer": record["signer"],
            "items": len(record["lengths"])}  # fmt: skip


def export_bytes(export: dict) -> bytes:
    from opentine.kernel import canonical_json

    return canonical_json(export) + b"\n"


def report(args: argparse.Namespace) -> tuple[dict, dict]:
    """``(row, export)``: the printed result and the export it is computed from."""
    from opentine._cli_lineage import _folder, trust
    from opentine._eval_stats import check
    from opentine._lineage import read_folder
    from opentine._lineage_trust import status
    from opentine._trends import compute
    from opentine._trends_collect import collect
    from opentine._trends_lengths import load

    check("paired-bootstrap", args.alpha, args.seed, args.resamples)
    if args.seed >= 2**53:
        raise ValueError("--seed must be below 2^53 (a browser reads it exactly)")
    files = read_folder(_folder(args), max_files=args.max_files, max_bytes=args.max_bytes)
    signers = trust(args)
    lengths = load(_lengths_path(args), Path(args.repo) / ".tine")
    export, excluded = collect(Path(args.repo), files, lengths=lengths["lengths"], trust=signers,
                               alpha=args.alpha, seed=args.seed, resamples=args.resamples,
                               loop=args.loop)  # fmt: skip
    result = compute(export)
    export = {**export, "reported": result}
    row = {"signers": status(signers), "lengths": {k: lengths[k] for k in ("status", "suite",
           "signer")}, "excluded": excluded,
           "export_sha256": hashlib.sha256(export_bytes(export)).hexdigest(), **result}  # fmt: skip
    return row, export


def _text(row: dict) -> str:
    lines = [f"trends: {len(row['variants'])} variants in {len(row['generations'])} generations "
             f"(signers {row['signers']}, task lengths {row['lengths']['status']})"]  # fmt: skip
    for gen in row["generations"]:
        best = gen["best"]
        lead = f"best {best['variant'][:19]} score {best['score']}" if best else "no clean variant"
        if best and best["horizon_minutes"]:
            lead += f" horizon {best['horizon_minutes']} min"
        lines.append(f"  gen {gen['generation']}: {gen['variants']} variants, {lead}, "
                     f"{gen['regressions']} regressions, {gen['flagged']} flagged")  # fmt: skip
    for reg in row["regressions"]:
        lines.append(f"  REGRESSION {reg['variant']} vs {reg['parent']}: "
                     f"{', '.join(reg['metrics'])}")  # fmt: skip
    for code in row["flags"]:
        lines.append(f"  flag {code}")
    return "\n".join(lines)


def cmd_trends(args: argparse.Namespace) -> None:
    from opentine._cli_json import emit
    from opentine._key_store import PassphraseUnavailable
    from opentine._signing_keys import SignatureError

    try:
        if args.sign_lengths:
            row, export = _sign(args), None
        else:
            row, export = report(args)
            if args.export:
                Path(args.export).write_bytes(export_bytes(export))
    except (PassphraseUnavailable, SignatureError, OSError, ValueError, KeyError) as exc:
        message = exc.args[0] if isinstance(exc, KeyError) and exc.args else exc
        raise error(message, prefix="trends: ") from exc
    if args.json:
        emit({"command": "trends", "schema": SCHEMA, **row})
    elif export is None:
        console.print(_terminal(f"SIGNED {row['signed']} ({row['items']} items)"), markup=False)
    else:
        console.print(_terminal(_text(row)), markup=False)
    if export is not None and args.fail_on_regression and row["regressions"]:
        raise SystemExit(1)


COMMANDS: dict[str, Callable[[argparse.Namespace], None]] = {"trends": cmd_trends}

__all__ = ["COMMANDS", "SCHEMA", "add_trends_parser", "cmd_trends", "export_bytes", "report"]
