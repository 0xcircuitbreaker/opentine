"""``tine sign --keyless`` and ``tine keyless verify`` (0.74).

``tine sign RUN --keyless`` is CI/runner mode: the OIDC identity token comes
from the environment only (``SIGSTORE_ID_TOKEN``, else the GitHub Actions
ambient token), never from argv. An ephemeral P-256 key is certified by Fulcio,
signs the run's in-toto statement, and the signature is logged to Rekor. The
output is the existing Sigstore bundle (``RUN.sigstore.json`` by default): leaf
and intermediates, the log entry, its inclusion proof and the signed tree head.

``tine keyless verify BUNDLE --fulcio-root PEM --rekor-key PEM [--run RUN]``
checks it offline (:mod:`opentine._keyless_check`). A keyless identity is never
trusted by default: only an owner-pinned trust bundle (``$OPENTINE_TRUST_OWNER``
or the config ``trust-owner`` file, SPEC 8.26) whose ``trust_policy`` names the
exact ``cert_oidc_issuer`` and ``cert_identity`` makes it ``keyless.trusted``.
Exit 0 only when trusted; 1 for a ``caveat:`` or ``fail:``; 2 for a usage error
or a pinned owner whose bundle is missing or bad (fail closed).
"""

from __future__ import annotations

import argparse
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

from opentine._cli_common import _terminal, console
from opentine._cli_errors import USAGE, error

SCHEMA = "tine-cli-keyless/1"


class _Routed(argparse.Action):
    """Store the flag and route ``tine sign`` to :func:`cmd_sign_any`.

    Only an invocation that names a keyless flag changes handler, so every
    existing ``tine sign`` call still reaches ``_cli_security.cmd_sign``.
    """

    def __call__(self, parser, namespace, values, option_string=None) -> None:
        setattr(namespace, self.dest, True if self.nargs == 0 else values)
        namespace.group_handler = cmd_sign_any


def add_sign_keyless_args(sign: argparse.ArgumentParser) -> None:
    help_ = "CI mode: sign with a Fulcio certificate for the OIDC token in the environment"
    sign.add_argument("--keyless", action=_Routed, nargs=0, default=False, help=help_)
    sign.add_argument("--rekor", action=_Routed, metavar="URL", help="--keyless: Rekor instance")
    sign.add_argument("--fulcio-url", action=_Routed, metavar="URL", help="--keyless: Fulcio")
    sign.add_argument("--output", action=_Routed, metavar="FILE", help="--keyless: bundle path")
    sign.add_argument("--json", action=_Routed, nargs=0, default=False, help="--keyless: JSON")


def add_keyless_parser(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser("keyless", help="Verify keyless (Fulcio + Rekor) signatures")
    verbs = parser.add_subparsers(dest="keyless_command", required=True)
    check = verbs.add_parser("verify", help="Verify a keyless bundle offline")
    check.add_argument("bundle", metavar="BUNDLE", help="A Sigstore bundle (.sigstore.json)")
    check.add_argument("--fulcio-root", required=True, metavar="PEM", help="Trusted CA certs")
    check.add_argument("--rekor-key", required=True, metavar="PEM", help="Trusted log key")
    check.add_argument("--run", metavar="RUN", help="Also require the bundle to name this run")
    help_ = "Owner-signed trust bundle (default .tine/trust-bundle.note)"
    check.add_argument("--trust-bundle", metavar="FILE", help=help_)
    check.add_argument("--json", action="store_true")


def pins(bundle_file: str | None) -> list[dict[str, str]]:
    """The owner-pinned keyless identities; none when no owner is pinned."""
    from opentine._key_roles_pin import _remember, _serials, bundle_path, owner_vkey
    from opentine._trust_bundle import BundleError, open_bundle

    owner = owner_vkey()
    if owner is None:
        return []
    path = Path(bundle_file) if bundle_file else bundle_path(Path(".tine"))
    try:
        payload = open_bundle(path.read_bytes(), owner, min_serial=_serials().get(owner, 0))
    except (OSError, BundleError) as exc:  # a pinned owner and no good bundle: fail closed
        raise error(f"trust bundle: {exc}", USAGE, prefix="keyless verify: ") from exc
    _remember(owner, payload["serial"])  # rollback floor, as for key roles
    return [payload["trust_policy"]]


def _sign(args: argparse.Namespace) -> None:
    from opentine._cli_common import _find_run
    from opentine._cli_sigstore import sign_for_export
    from opentine._export_write import write_private
    from opentine._graph_serde import verify_integrity
    from opentine._signing_v4 import statement_for
    from opentine.core import Run

    stray = [f for f in ("key_env", "key_file", "ed25519_key_file", "key_id", "signer", "save")
             if getattr(args, f, None)]  # fmt: skip
    if stray or args.algorithm != "hmac-sha256":
        bad = ", ".join(f"--{f.replace('_', '-')}" for f in stray) or "--algorithm"
        raise error(f"{bad} has no effect with --keyless: the key is ephemeral", 1,
                    prefix="sign: ")  # fmt: skip
    path = _find_run(args.run_id)
    if not path:
        raise error(f"Run not found: {args.run_id}", prefix="sign: ")
    output = Path(args.output) if args.output else Path(f"{path}.sigstore.json")
    if output.exists() and not args.overwrite:
        raise error(f"{output} already exists; pass --overwrite", prefix="sign: ")
    args.identity_token = None  # CI mode: the token comes from the environment only
    args.keyless_chain = True
    try:
        integrity = verify_integrity(path)
        if not integrity.ok:
            raise ValueError(f"run fails integrity: {integrity.reason}")
        statement = statement_for(Run.load(path), integrity.actual, None)
        bundle = sign_for_export(args, statement, lambda: None)
        line = json.dumps(bundle, sort_keys=True, separators=(",", ":"))
        write_private(output, (line + "\n").encode("ascii"))
    except (OSError, ValueError) as exc:
        raise error(exc, prefix="sign: ") from exc
    entry = (bundle["verificationMaterial"]["tlogEntries"] or [{}])[0]
    row = {"command": "sign", "schema": SCHEMA, "mode": "keyless", "run": str(path),
           "bundle": output.as_posix(), "log_index": int(entry.get("logIndex", -1))}  # fmt: skip
    if args.json:
        from opentine._cli_json import emit

        emit(row)
    else:
        console.print(f"Signed keyless: {_terminal(output.as_posix())}", markup=False)


def _verify(args: argparse.Namespace) -> dict[str, Any]:
    from opentine._fulcio_verify import load_roots
    from opentine._json_shallow import loads as shallow_loads
    from opentine._keyless_check import KeylessFail, check
    from opentine._rekor_proof import load_log_key

    try:
        roots = load_roots(Path(args.fulcio_root).read_bytes())
        log_key = load_log_key(Path(args.rekor_key).read_bytes())
        document = shallow_loads(Path(args.bundle).read_bytes().splitlines()[0])
    except (OSError, ValueError, IndexError) as exc:
        raise error(exc, USAGE, prefix="keyless verify: ") from exc
    pinned = pins(args.trust_bundle)
    try:
        row = check(document, roots=roots, log_key=log_key, pins=pinned)
    except KeylessFail as exc:
        return {"outcome": "fail", "code": exc.code, "reason": str(exc), "trusted": False}
    if args.run:
        from opentine.intoto import check_subject

        statement = {"subject": [row["subject"]]}
        if (why := check_subject(statement, args.run)) is not None:
            return {"outcome": "fail", "code": "fail:keyless-subject", "reason": why,
                    "trusted": False}  # fmt: skip
    return row


def cmd_keyless(args: argparse.Namespace) -> None:
    row = {"command": "keyless verify", "schema": SCHEMA, "bundle": args.bundle, **_verify(args)}
    if args.json:
        from opentine._cli_json import emit

        emit(row)
    else:
        console.print(f"{row['code']}: {_terminal(row['reason'])}", markup=False)
        if "assurance_tier" in row:
            ident = row["identity"]
            who = _terminal(f"issuer {ident['issuer']}; identity {', '.join(ident['san'])}")
            console.print(f"  tier {row['assurance_tier']}; {who}", markup=False)
    if not row["trusted"]:
        raise SystemExit(1)


def cmd_sign_any(args: argparse.Namespace) -> None:
    """``tine sign``: keyless when asked, else the legacy key-signing path."""
    if getattr(args, "keyless", False):
        return _sign(args)
    stray = [f for f in ("rekor", "fulcio_url", "output", "json") if getattr(args, f, None)]
    if stray:
        bad = ", ".join(f"--{f.replace('_', '-')}" for f in stray)
        raise error(f"{bad} has no effect without --keyless", 1, prefix="sign: ")
    from opentine._cli_security import cmd_sign

    cmd_sign(args)


COMMANDS: dict[str, Callable[[argparse.Namespace], None]] = {"keyless": cmd_keyless}
