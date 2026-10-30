"""``tine export --format intoto`` and ``tine verify --attestation``.

Export writes a signed DSSE envelope (one ``.intoto.jsonl`` line) carrying an
in-toto Statement about the run -- see :mod:`opentine.intoto`. It needs an
Ed25519 key, ``--ed25519-key-file`` or ``--agent NAME``: an unsigned in-toto
statement is a claim anyone can write, so none is produced.

Verify checks such a file against a run, fail-closed: the signature must verify
under ``--pubkey``, a ``--pin``-ned fingerprint, or ``--trust-embedded-key``
(trust-on-first-use of the ``did:key`` keyid, reported as ``verified-tofu``);
and the run artifact's recomputed digest must equal the statement's subject.
Anything else exits 1. HMAC keys are refused: DSSE here is Ed25519 only.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from opentine._cli_common import BRAND, _find_run, _terminal, console
from opentine._cli_flags import _require_output_slot, refuse_unhonoured
from opentine._signing_keys import SignatureError, ed25519_private_from_file

__all__ = [
    "add_intoto_export_args",
    "add_attestation_verify_args",
    "cmd_export_intoto",
    "cmd_verify_attestation",
    "export_intoto",
]


def add_intoto_export_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--ed25519-key-file", metavar="PATH", help="--format intoto: sign with this Ed25519 key"
    )
    parser.add_argument(
        "--agent", metavar="NAME", help="--format intoto: sign with the key from keygen --agent"
    )


def add_attestation_verify_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--attestation",
        metavar="FILE",
        help="Check an in-toto/DSSE .intoto.jsonl attestation for this run",
    )


def _fail(message: str, code: int = 1) -> None:
    console.print(f"[red]{_terminal(message)}[/]")
    raise SystemExit(code)


def _signing_key(args: argparse.Namespace):
    key_file, agent = getattr(args, "ed25519_key_file", None), getattr(args, "agent", None)
    if key_file and agent:
        _fail("--ed25519-key-file and --agent cannot be combined: one envelope, one key.")
    if agent:
        from opentine._agent_keys import key_paths

        key_file = str(key_paths(agent)[0])
    if not key_file:
        _fail("--format intoto needs a signing key: --ed25519-key-file PATH or --agent NAME.")
    return ed25519_private_from_file(key_file)


def export_intoto(args: argparse.Namespace) -> bool:
    """Run ``--format intoto`` and return True; otherwise refuse its signing flags."""
    if args.format == "intoto":
        cmd_export_intoto(args)
        return True
    refuse_unhonoured(
        args,
        ("ed25519_key_file", "agent"),
        mode="unless --format intoto",
        hint="They sign an in-toto attestation; other formats are unsigned.",
    )
    return False


def cmd_export_intoto(args: argparse.Namespace) -> None:
    refuse_unhonoured(
        args,
        ("endpoint", "compress", "allow_insecure"),
        mode="with --format intoto",
        hint="The attestation is one signed JSON line, written to stdout or --output.",
    )
    from opentine._export_write import unsafe_destination, write_private
    from opentine._graph_serde import verify_integrity
    from opentine.core import Run
    from opentine.intoto import build_statement, sign_statement

    output = Path(args.output) if args.output else None
    if output is None:
        refuse_unhonoured(
            args, ("force",), mode="without --output", hint="Stdout replaces nothing."
        )
    else:
        _require_output_slot(output, args.force)
        if reason := unsafe_destination(output):
            _fail(f"Refusing to export: {reason}: {output}")
    path = _find_run(args.run_id)
    if not path:
        _fail(f"Run not found: {args.run_id}")
    try:
        key = _signing_key(args)
        integrity = verify_integrity(path)
        if not integrity.ok:  # never attest to bytes that are not what they claim
            raise ValueError(f"run fails integrity: {integrity.reason}")
        envelope = sign_statement(build_statement(Run.load(path), integrity.actual), key)
    except (OSError, SignatureError, ValueError) as exc:
        _fail(f"Export failed: {exc}")
        return
    import json

    line = json.dumps(envelope, sort_keys=True, separators=(",", ":"))
    if output is None:
        print(line)
        return
    try:
        write_private(output, (line + "\n").encode("ascii"))
    except OSError as exc:
        _fail(f"Export failed: {exc}")
    console.print(f"[{BRAND}]# Exported[/] in-toto attestation [{BRAND}]to[/] {_terminal(output)}")


def _trust(args: argparse.Namespace):
    if getattr(args, "key_env", None) or getattr(args, "key_file", None):
        _fail("--attestation is Ed25519-signed: pass --pubkey, --pin or --trust-embedded-key.")
    from opentine._signing_pins import normalize_pins
    from opentine.signing import ed25519_public_from_file

    try:
        pins = normalize_pins(getattr(args, "pin", None))
        public = ed25519_public_from_file(args.pubkey) if getattr(args, "pubkey", None) else None
    except (OSError, SignatureError, ValueError) as exc:
        _fail(f"SIGNATURE FAILED cannot read the key: {exc}")
    trust_embedded = bool(getattr(args, "trust_embedded_key", False))
    if public is None and not pins and not trust_embedded:
        _fail("--attestation needs a trusted key: --pubkey, --pin or --trust-embedded-key.")
    return public, (pins if public is None else frozenset()), trust_embedded


def _report(args, attestation, path, result, subject_error) -> None:
    ok = result.ok and subject_error is None
    if getattr(args, "json", False):
        from opentine._cli_json import emit

        statement = result.statement or {}
        emit(
            {
                "command": "verify",
                "attestation": str(attestation),
                "path": str(path) if path else None,
                "ok": ok,
                "signature": {
                    "status": result.status,
                    "reason": result.reason,
                    "keyid": result.keyid,
                    "key_fingerprint": result.key_fingerprint,
                },
                "subject": {"ok": result.ok and subject_error is None, "reason": subject_error},
                "predicate_type": statement.get("predicateType"),
                "subject_digest": (statement.get("subject") or [{}])[0].get("digest"),
            }
        )
    elif ok:
        console.print(
            f"[green]OK[/] {_terminal(attestation)} {result.status} "
            f"keyid={_terminal(result.keyid)} subject={_terminal(path)}"
        )
    else:
        reason = subject_error if result.ok else f"{result.status}: {result.reason}"
        console.print(f"[red]ATTESTATION FAILED[/] {_terminal(attestation)}: {_terminal(reason)}")
    if not ok:
        raise SystemExit(1)


def cmd_verify_attestation(args: argparse.Namespace) -> None:
    from opentine.intoto import EnvelopeResult, check_subject, read_envelopes, verify_envelope

    public, pins, trust_embedded = _trust(args)
    path = _find_run(args.run_id)
    try:
        envelopes = read_envelopes(args.attestation)
        if len(envelopes) != 1:
            raise ValueError(f"expected one envelope, found {len(envelopes)}")
        result = verify_envelope(
            envelopes[0], public_key=public, pins=pins, trust_embedded=trust_embedded
        )
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        result = EnvelopeResult(False, "error", f"cannot read attestation: {exc}")
    subject_error = None
    if result.ok:
        subject_error = (
            check_subject(result.statement, path) if path else f"run not found: {args.run_id}"
        )
    _report(args, args.attestation, path, result, subject_error)
