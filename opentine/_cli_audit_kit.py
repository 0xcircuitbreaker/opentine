"""``tine audit-kit build|verify`` (0.49): the air-gapped audit kit.

``build RUN... | BUNDLE --out DIR`` writes the kit described in
:mod:`opentine._audit_kit`; ``--zip`` also writes ``DIR.zip``. ``verify
DIR|ZIP`` re-checks it with the network refused (:mod:`opentine._audit_kit_check`);
``--pyz`` also runs the kit's own ``tine-verify.pyz`` in a separate process.
``--json`` writes ``tine-cli-audit-kit-build-1`` / ``tine-cli-audit-kit-verify-1``.
Both exit 1 when a check fails (``build`` after writing the kit).
"""

from __future__ import annotations

import argparse
import hashlib
import tempfile
from pathlib import Path
from typing import Any

from rich.markup import escape

from opentine._cli_common import _find_run, _terminal, console
from opentine._cli_errors import NOT_FOUND, USAGE, fail


def add_audit_kit_parser(sub: Any) -> None:
    kit = sub.add_parser("audit-kit", help="Build or verify an air-gapped audit kit")
    actions = kit.add_subparsers(dest="audit_kit_command", required=True)
    build = actions.add_parser("build", help="Write a self-contained offline audit kit")
    build.add_argument("targets", nargs="+", metavar="RUN|BUNDLE", help="Runs or one bundle")
    build.add_argument("--out", required=True, metavar="DIR", help="New or empty directory")
    build.add_argument("--zip", action="store_true", help="Also write DIR.zip")
    build.add_argument("--pubkey", help="Trusted Ed25519 public key for the run signatures")
    build.add_argument("--pin", action="append", metavar="FINGERPRINT", help="Pinned key")
    build.add_argument("--action-policy", metavar="FILE", help="Action policy to check")
    build.add_argument("--trusted-root", metavar="FILE", help="Sigstore trusted_root.json")
    build.add_argument("--sign", metavar="KEY", help="Ed25519 key file: sign the custody record")
    build.add_argument("--attest-key", metavar="KEY", help="Replay now; sign a replay/v1 DSSE")
    build.add_argument("--replay-attestation", metavar="FILE", help="Existing replay/v1 DSSE")
    build.add_argument("--replay-pubkey", metavar="FILE", help="Signer key of that DSSE")
    build.add_argument("--witness", action="append", metavar="VKEY", help="Pinned witness key")
    build.add_argument("--witness-set", metavar="FILE", help="File of witness vkeys, one a line")
    build.add_argument("--log-key", action="append", metavar="FILE", help="Pinned log key file")
    build.add_argument("--quorum", metavar="N-of-M", help="Cosignatures the witness set needs")
    build.add_argument("--operator", help="Who is building (default: the login name)")
    build.add_argument("--json", action="store_true")
    verify = actions.add_parser("verify", help="Re-check a kit offline")
    verify.add_argument("kit", metavar="DIR|ZIP", help="Kit directory or zip")
    verify.add_argument("--pyz", action="store_true", help="Also run the kit's tine-verify.pyz")
    verify.add_argument("--json", action="store_true")


def _is_bundle(path: Path) -> bool:
    from opentine._bundle import MAGIC

    try:
        with path.open("rb") as handle:
            return handle.read(len(MAGIC)) == MAGIC
    except OSError:
        return False


def _sources(args: argparse.Namespace, room: Path) -> tuple[list[Path], dict[str, Any]]:
    from opentine import _audit_kit_parts as parts
    from opentine._bundle import BundleError

    first = Path(args.targets[0])
    if first.is_file() and _is_bundle(first):
        if len(args.targets) != 1:
            fail("a bundle is the kit's only input", USAGE)
        try:
            files, verified = parts.bundle_runs(first, room)
        except (BundleError, OSError, ValueError) as exc:
            fail(f"bundle does not verify: {exc}")
        if not files:
            fail("the bundle carries no run")
        digest = parts.sha256_file(first)
        source = {"kind": "bundle", "name": first.name, "sha256": digest}
        return files, {"source": source, "bundle": first, "pre_checks": [verified]}
    files = []
    for name in args.targets:
        path = _find_run(name)
        if path is None:
            fail(f"Run not found: {name}", NOT_FOUND)
        if any(p.name == Path(path).name for p in files):
            fail(f"two runs share the file name {Path(path).name}; build them separately")
        files.append(Path(path))
    combined = hashlib.sha256(b"".join(p.read_bytes() for p in files)).hexdigest()
    label = files[0].name if len(files) == 1 else f"{len(files)} runs"
    return files, {"source": {"kind": "run", "name": label, "sha256": combined}}


def _witnesses(args: argparse.Namespace) -> list[str]:
    keys = list(args.witness or [])
    if args.witness_set:
        text = Path(args.witness_set).read_text(encoding="utf-8")
        keys += [line.strip() for line in text.splitlines() if line.strip()]
    return keys


def _build(args: argparse.Namespace) -> None:
    from opentine._audit_kit import build_kit, write_zip
    from opentine._cli_evidence import _login, _verify_args
    from opentine._cli_json import emit
    from opentine._signing_keys import SignatureError, ed25519_private_from_file
    from opentine._version import __version__

    out = Path(args.out)
    if out.exists() and (not out.is_dir() or any(out.iterdir())):
        fail(f"--out must be a new or empty directory: {out}", USAGE)
    if args.attest_key and args.replay_attestation:
        fail("pass --attest-key (replay now) or --replay-attestation, not both", USAGE)
    if args.replay_attestation and not (args.replay_pubkey or args.pubkey):
        fail("--replay-attestation needs --replay-pubkey (or --pubkey) to be checked", USAGE)
    with tempfile.TemporaryDirectory(prefix="tine-kit-src-") as room:
        sources, extra = _sources(args, Path(room))
        try:
            key = ed25519_private_from_file(args.sign) if args.sign else None
            opts = {**extra, "verify_args": _verify_args(args), "version": __version__,
                    "trust_files": _trust(args), "operator": args.operator or _login(),
                    "signing_key": key, "witnesses": _witnesses(args),
                    "log_keys": [Path(p) for p in args.log_key or []], "quorum": args.quorum,
                    "attest_key": _path(args.attest_key),
                    "replay_copy": _path(args.replay_attestation),
                    "replay_pubkey": _path(args.replay_pubkey or args.pubkey)}  # fmt: skip
            summary = build_kit(out, sources, opts)
        except (OSError, SignatureError, ValueError) as exc:
            fail(f"cannot build the audit kit: {exc}")
    archive = out.with_name(out.name + ".zip") if args.zip else None
    if archive is not None:
        write_zip(out, archive)
    if args.json:
        emit({**summary, "zip": archive.name if archive else None})
    else:
        verdict = "[green]pass[/]" if summary["ok"] else "[red]FAIL[/]"
        files = summary["files"]
        console.print(f"Audit kit written to {_terminal(out)} ({files} files): {verdict}")
        if archive is not None:
            console.print(f"zip: {_terminal(archive)}")
    if not summary["ok"]:
        raise SystemExit(1)


def _path(value: str | None) -> Path | None:
    return Path(value) if value else None


def _trust(args: argparse.Namespace) -> dict[str, Path]:
    trust = {"pubkey.pub": Path(args.pubkey)} if args.pubkey else {}
    if args.action_policy:
        trust["action-policy" + Path(args.action_policy).suffix] = Path(args.action_policy)
    if args.trusted_root:
        trust["trusted_root.json"] = Path(args.trusted_root)
    return trust


def _verify(args: argparse.Namespace) -> None:
    from opentine._audit_kit_check import verify_kit
    from opentine._cli_json import emit

    target = Path(args.kit)
    if not target.exists():
        fail(f"no such kit: {args.kit}", NOT_FOUND)
    try:
        result = verify_kit(target, with_pyz=args.pyz)
    except (OSError, ValueError) as exc:
        fail(f"cannot read the kit: {exc}")
    if args.json:
        emit(result)
    else:
        colors = {"pass": "green", "fail": "red", "skip": "yellow"}
        for row in result["checks"]:
            color = colors[row["outcome"]]
            text = escape(f"{row['name']}: {row['detail']}")
            console.print(f"[{color}]{row['outcome']:>4}[/]  {text}", highlight=False)
        console.print("PASS" if result["ok"] else "[red]FAIL[/]")
    if not result["ok"]:
        raise SystemExit(1)


def cmd_audit_kit(args: argparse.Namespace) -> None:
    (_build if args.audit_kit_command == "build" else _verify)(args)


COMMANDS = {"audit-kit": cmd_audit_kit}

__all__ = ["COMMANDS", "add_audit_kit_parser", "cmd_audit_kit"]
