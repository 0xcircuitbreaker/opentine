"""``tine verify RUN --offline [--json] [--report FILE] [--strict]``.

Chains every check that can run without a network -- digest, signature,
attestation, stored Rekor receipt, certificate chain and SCT, action manifest
and action policy -- into one ``tine-verify-report/1`` (``_verify_report``).
The whole chain runs inside ``_offline_guard.no_network``: a socket connect or
name lookup raises, and the report records ``offline.network-refused``.

Without ``--offline``, ``--strict``, ``--report`` and ``--action-policy`` are
refused by name and ``tine verify`` behaves exactly as before.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from opentine._cli_flags import refuse_unhonoured

OFFLINE_DESTS = (
    "strict",
    "report",
    "action_policy",
    "locate",
    "provenance_source",
    "tsa_roots",
    "hermetic",
)


def add_offline_verify_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Run every check that needs no network; write a tine-verify-report/1",
    )
    parser.add_argument(
        "--strict", action="store_true", help="--offline: fail if a required check cannot run"
    )
    parser.add_argument("--report", metavar="FILE", help="--offline: also write the JSON report")
    parser.add_argument(
        "--locate", action="store_true", help="--offline: localise a broken digest or signature"
    )
    parser.add_argument(
        "--source",
        dest="provenance_source",
        metavar="PATH",
        help="--offline: re-hash and re-verify the source a v4 run was upgraded from",
    )
    parser.add_argument(
        "--action-policy", metavar="FILE", help="--offline: check the run's actions against it"
    )
    parser.add_argument(
        "--tsa-roots", metavar="FILE.pem", help="--offline: trusted TSA roots for timestamp tokens"
    )
    parser.add_argument(
        "--hermetic",
        action="store_true",
        help="--offline: re-run inside an OS no-network sandbox (exit 6 if unsupported)",
    )


def add_verify_args(parser: argparse.ArgumentParser) -> None:
    """Every ``tine verify`` flag beyond the key flags: attestation and offline."""
    from opentine._assurance_cli import add_assurance_verify_args
    from opentine._cli_intoto import add_attestation_verify_args

    add_attestation_verify_args(parser)
    add_offline_verify_args(parser)
    add_assurance_verify_args(parser)


def refuse_without_offline(args: argparse.Namespace) -> None:
    # --tsa-roots also feeds the assurance tier (T3), so a floor honours it.
    exempt = ("tsa_roots",) if getattr(args, "min_assurance", None) else ()
    dests = tuple(dest for dest in OFFLINE_DESTS if dest not in exempt)
    refuse_unhonoured(
        args, dests, mode="without --offline", hint="Add --offline to run that report."
    )


def cmd_verify_offline(args: argparse.Namespace) -> None:
    from opentine._cli_common import _find_run, console
    from opentine._cli_json import emit, serialize
    from opentine._cli_sigstore import VERIFY_DESTS
    from opentine._verify_report import render

    if getattr(args, "hermetic", False):
        from opentine._hermetic import reexec_hermetic

        reexec_hermetic()
    if getattr(args, "attestation", None):
        from opentine._keyless_root import refuse_root_conflicts

        refuse_root_conflicts(args)
    else:
        refuse_unhonoured(
            args,
            VERIFY_DESTS,
            mode="without --attestation",
            hint="They check an in-toto attestation's receipt or certificate.",
        )
    from opentine._verify_chain import build_report

    if Path(args.run_id).is_dir():
        from opentine._verify_dataset import build_dataset

        report = build_dataset(args, Path(args.run_id))
    else:
        path = _find_run(args.run_id)
        report = build_report(args, Path(path) if path else None, args.run_id)
    document = report.as_json()
    if getattr(args, "report", None):
        from opentine._export_write import write_private

        text = serialize(document) + "\n"
        try:
            write_private(Path(args.report), text.encode("utf-8"))
        except (OSError, ValueError) as exc:
            console.print(f"[red]cannot write --report: {exc}[/]")
            raise SystemExit(1) from exc
    if getattr(args, "json", False):
        emit(document)
    else:
        for line in report.lines() if hasattr(report, "lines") else render(report):
            console.print(line)
    if not report.ok:
        raise SystemExit(1)
    if getattr(report, "assurance", None) is not None:  # a dataset has one per run
        from opentine._assurance_cli import enforce_floor

        enforce_floor(args, report.assurance)


__all__ = [
    "OFFLINE_DESTS",
    "add_offline_verify_args",
    "add_verify_args",
    "refuse_without_offline",
    "cmd_verify_offline",
]
