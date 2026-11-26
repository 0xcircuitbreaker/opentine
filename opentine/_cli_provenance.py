"""``tine provenance embed|verify`` (0.84): provenance for produced artifacts.

``embed ARTIFACT --run RUN --key KEY`` writes an in-file pointer to the run where
the format has a metadata slot (PNG text chunk, JPEG comment, PDF ``/Info``),
optionally a C2PA manifest (``--c2pa-cert CHAIN --c2pa-key KEY``, the ``c2pa``
extra), and a signed sidecar ``ARTIFACT.provenance.json`` that is also held as
an attestation on the run. ``verify ARTIFACT`` checks the sidecar's signature
and signer role, the artifact digest, the pointer, the C2PA manifest and the
run; it exits 1 on any finding. See docs/PROVENANCE.md.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable
from pathlib import Path
from typing import Any

from opentine._cli_common import _terminal, console
from opentine._cli_errors import error

SCHEMA = "tine-cli-provenance/1"
MAX_PEM = 64 * 1024


def add_provenance_parser(subparsers: argparse._SubParsersAction) -> None:
    from opentine._artifact_c2pa import ALGS
    from opentine._artifact_provenance import SUBJECTS

    parser = subparsers.add_parser("provenance", help="Provenance for produced artifacts")
    verbs = parser.add_subparsers(dest="provenance_command", required=True)
    embed = verbs.add_parser("embed", help="Point an artifact at its run and sign a sidecar")
    embed.add_argument("--run", required=True, metavar="RUN", help="The run that produced it")
    embed.add_argument("--key", required=True, metavar="KEY", help="Ed25519 private key")
    embed.add_argument("--subject", default="artifact", choices=SUBJECTS, help="What it is")
    embed.add_argument("--dataset-version", metavar="ATTESTATION",
                       help="The held dataset version (0.75) this artifact is")  # fmt: skip
    embed.add_argument("--no-pointer", action="store_true", help="The sidecar only")
    embed.add_argument("--c2pa-cert", metavar="PEM", help="C2PA signing certificate chain")
    embed.add_argument("--c2pa-key", metavar="PEM", help="C2PA signing private key")
    embed.add_argument("--c2pa-alg", default="es256", choices=ALGS, help="C2PA algorithm")
    verify = verbs.add_parser("verify", help="Check an artifact against its signed sidecar")
    for verb in (embed, verify):
        verb.add_argument("artifact", metavar="ARTIFACT", help="The produced file")
        verb.add_argument("--sidecar", metavar="PATH", help="Default: ARTIFACT.provenance.json")
        verb.add_argument("--repo", default=".", metavar="PATH", help="Repository")
        verb.add_argument("--json", action="store_true", help="Print a JSON object")


def _pem(path: str) -> bytes:
    with open(path, "rb") as handle:
        data = handle.read(MAX_PEM + 1)
    if len(data) > MAX_PEM:
        raise ValueError(f"{path} is larger than {MAX_PEM} bytes")
    return data


def _embed(args: argparse.Namespace, repo: Any) -> tuple[dict[str, Any], list[str]]:
    from opentine import _artifact_provenance_ops as ops
    from opentine._key_hygiene import ed25519_private
    from opentine.repository.ops import resolve_target

    if bool(args.c2pa_cert) != bool(args.c2pa_key):
        raise ValueError("--c2pa-cert and --c2pa-key go together")
    signing = None
    if args.c2pa_cert:
        signing = {"cert_chain": _pem(args.c2pa_cert), "private_key": _pem(args.c2pa_key),
                   "alg": args.c2pa_alg}  # fmt: skip
    run = resolve_target(repo, args.run)
    body = ops.embed(repo, Path(args.artifact), run=run, key=ed25519_private(args.key),
                     subject=args.subject, pointer=not args.no_pointer,
                     dataset_version=args.dataset_version, c2pa_signing=signing,
                     sidecar=args.sidecar)  # fmt: skip
    where = body["pointer"] or "no pointer slot"
    return body, [f"{body['artifact']}: {body['digest']} -> {run} ({where}"
                  f"{', C2PA' if body['c2pa'] else ''}); sidecar {body['sidecar']}"]  # fmt: skip


def _verify(args: argparse.Namespace, repo: Any) -> tuple[dict[str, Any], list[str]]:
    from opentine import _artifact_provenance_ops as ops

    body = ops.verify(repo, Path(args.artifact), sidecar=args.sidecar)
    lines = [f"{f['code']}: {f['message']}" for f in body["findings"]]
    return body, lines or [f"OK {body['artifact']} {body['digest']} from {body['run']}"]


def cmd_provenance(args: argparse.Namespace) -> None:
    from opentine._cli_json import emit
    from opentine.repo import Repo

    verb = args.provenance_command
    try:
        body, lines = {"embed": _embed, "verify": _verify}[verb](args, Repo.open(args.repo))
    except (OSError, KeyError, ValueError, RuntimeError) as exc:
        raise error(exc, prefix=f"provenance {verb}: ") from exc
    if args.json:
        emit({"command": f"provenance {verb}", "schema": SCHEMA, **body})
    else:
        for line in lines:
            console.print(_terminal(line), markup=False)
    if verb == "verify" and not body["ok"]:
        raise SystemExit(1)


COMMANDS: dict[str, Callable[[argparse.Namespace], None]] = {"provenance": cmd_provenance}

__all__ = ["COMMANDS", "SCHEMA", "add_provenance_parser", "cmd_provenance"]
