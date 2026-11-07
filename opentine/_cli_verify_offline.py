"""``tine verify RUN --offline [--json] [--report FILE] [--strict]``.

Chains every check that can run without a network -- digest, signature,
attestation, stored Rekor receipt, certificate chain and SCT, action manifest
and action policy -- into one ``tine-verify-report/2`` (``_verify_report``).
``--report PATH --sign-key KEY`` writes it signed (X22, ``_verify_report_sign``);
``--timestamp`` also writes ``PATH.tsdata``, the bytes a TSA token over that
signature must cover (``tine verify-report attach`` stores the response).
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
    "tsa_policy",
    "hermetic",
    "sign_key",
    "timestamp",
    "witnesses",  # 0.44 X33 (``_cli_verify_tlog``)
    "witness_vkey",
    "log_vkey",
)


def add_offline_verify_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Run every check that needs no network; write a tine-verify-report/2",
    )
    parser.add_argument(
        "--strict", action="store_true", help="--offline: fail if a required check cannot run"
    )
    parser.add_argument("--report", metavar="FILE", help="--offline: also write the JSON report")
    parser.add_argument(
        "--sign-key", metavar="KEY", help="--report: sign the report with this Ed25519 key file"
    )
    parser.add_argument(
        "--timestamp",
        action="store_true",
        help="--sign-key: also write REPORT.tsdata, the bytes a TSA token must cover",
    )
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
        "--tsa-policy",
        action="append",
        metavar="OID",
        help="--offline: accept only timestamp tokens issued under this TSA policy OID",
    )
    parser.add_argument(
        "--hermetic",
        action="store_true",
        help="--offline: re-run inside an OS no-network sandbox (exit 6 if unsupported)",
    )
    from opentine._cli_verify_tlog import add_tlog_verify_args

    add_tlog_verify_args(parser)


def add_verify_args(parser: argparse.ArgumentParser) -> None:
    """Every ``tine verify`` flag beyond the key flags: attestation and offline."""
    from opentine._assurance_cli import add_assurance_verify_args
    from opentine._cli_intoto import add_attestation_verify_args

    add_attestation_verify_args(parser)
    parser.add_argument(
        "--allow-stale-root",
        action="store_true",
        help="Use the installed TUF trusted root even when its metadata has expired",
    )
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
    if getattr(args, "witnesses", None):
        from opentine._cli_verify_tlog import cmd_verify_tlog

        return cmd_verify_tlog(args)
    refuse_unhonoured(
        args,
        ("witness_vkey", "log_vkey"),
        mode="without --witnesses",
        hint="Add --witnesses N-of-M.",
    )
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
    if getattr(args, "sign_key", None) and not getattr(args, "report", None):
        from opentine._cli_errors import USAGE, fail

        fail("--sign-key signs the --report file; pass --report PATH", USAGE)
    if getattr(args, "report", None):
        _write_report(args, document, serialize(document) + "\n")
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


def _write_report(args: argparse.Namespace, document: dict, text: str) -> None:
    from opentine._cli_errors import USAGE, fail
    from opentine._export_write import write_private

    if getattr(args, "timestamp", False) and not getattr(args, "sign_key", None):
        fail("--timestamp needs --sign-key: a token covers the report's signature", USAGE)
    data = text.encode("utf-8")
    if getattr(args, "sign_key", None):
        from opentine import _verify_report_sign as signed
        from opentine._signing_keys import SignatureError, ed25519_private_from_file

        try:
            document = signed.sign_report(document, ed25519_private_from_file(args.sign_key))
        except (OSError, SignatureError, ValueError) as exc:
            fail(f"cannot sign --report with --sign-key: {exc}", cause=exc)
        data = signed.dumps(document)
    try:
        write_private(Path(args.report), data)
        if getattr(args, "timestamp", False):
            stamp = Path(args.report + ".tsdata")
            write_private(stamp, signed.bound(document).encode("utf-8"))
    except (OSError, ValueError) as exc:
        fail(f"cannot write --report: {exc}", cause=exc)


__all__ = [
    "OFFLINE_DESTS",
    "add_offline_verify_args",
    "add_verify_args",
    "refuse_without_offline",
    "cmd_verify_offline",
]
