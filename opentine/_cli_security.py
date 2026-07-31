"""Integrity verification, signing, and key generation commands."""

from __future__ import annotations

import argparse
from pathlib import Path

from opentine._canon import atomic_write_text
from opentine._cli_common import BRAND, _find_run, _terminal, console
from opentine._cli_flags import KEY_MATERIAL_FLAGS, refuse_conflict, refuse_unhonoured
from opentine._cli_json import emit_verify
from opentine.core import Run, short_id
from opentine.signing import (
    SignatureError,
    ed25519_private_from_file,
    ed25519_public_from_file,
    generate_ed25519,
    hmac_key_from_env,
    hmac_key_from_file,
)


def cmd_verify(args: argparse.Namespace) -> None:
    refuse_conflict(
        args, ("key_env", "key_file"), hint="Both name an HMAC key; pass the one you mean."
    )
    refuse_conflict(
        args,
        KEY_MATERIAL_FLAGS,
        hint="One signature is checked against one key, and the artifact would pick which.",
    )
    path = _find_run(args.run_id)
    as_json = getattr(args, "json", False)
    if not path:
        result = Run.verify_integrity(args.run_id)
        if as_json:
            emit_verify(args.run_id, result, None)
            raise SystemExit(1)
        console.print(f"[red]FAILED[/] {_terminal(args.run_id)}: {_terminal(result.reason)}")
        raise SystemExit(1)
    result = Run.verify_integrity(path)
    if as_json:
        # One object covering both checks, so a script never has to parse prose.
        # Ordered exactly like the human path below: integrity is the gate, so a
        # failed digest is reported without any authenticity claim beside it.
        armed = result.ok and signature_requested(args)
        signature = signature_result(args, path) if armed else None
        emit_verify(path, result, signature)
        if not result.ok or (signature is not None and not signature.ok):
            raise SystemExit(1)
        return
    if not result.ok:
        console.print(f"[red]FAILED[/] {_terminal(path)}: {_terminal(result.reason)}")
        if result.expected:
            console.print(f"[dim]expected:[/] {_terminal(result.expected)}")
        if result.actual:
            console.print(f"[dim]actual:[/] {_terminal(result.actual)}")
        raise SystemExit(1)
    digest = result.actual or result.expected or ""
    draft = " [yellow](draft / autosave checkpoint)[/]" if result.draft else ""
    console.print(f"[green]OK[/] {_terminal(path)} sha256:{_terminal(digest[:12])}{draft}")
    _verify_signature_if_requested(args, path)


def signature_requested(args: argparse.Namespace) -> bool:
    """Whether any flag arms the authenticity check.

    --trust-embedded-key is itself a request to check authenticity (TOFU), so it
    arms the check like any key would; leaving it out of this test made
    `tine verify RUN --trust-embedded-key` exit 0 without verifying anything.
    repository/_migration.py already treats trust_embedded as a verification request.
    Spelled once so the human and --json paths can never disagree about it.
    """
    return bool(
        getattr(args, "key_env", None)
        or getattr(args, "key_file", None)
        or getattr(args, "pubkey", None)
        or getattr(args, "trust_embedded_key", False)
        or getattr(args, "require_signature", False)
    )


def signature_result(args: argparse.Namespace, path: Path):
    """Run the armed signature check, exiting 1 if the key material is unreadable."""
    key_env = getattr(args, "key_env", None)
    key_file = getattr(args, "key_file", None)
    public_path = getattr(args, "pubkey", None)
    trust_embedded = getattr(args, "trust_embedded_key", False)
    try:
        hmac_key = hmac_key_from_env(key_env) if key_env else None
        if key_file:
            hmac_key = hmac_key_from_file(key_file)
        public = ed25519_public_from_file(public_path) if public_path else None
    # OSError as well as SignatureError: a --key-file/--pubkey path that is missing,
    # a directory, or unreadable came out as an interpreter traceback, which is the
    # single most likely way to mistype one of these options.
    except (OSError, SignatureError) as exc:
        console.print(f"[red]SIGNATURE FAILED[/] cannot read the key: {_terminal(exc)}")
        raise SystemExit(1) from exc
    return Run.verify_signature(
        path, hmac_key=hmac_key, public_key=public, trust_embedded=trust_embedded
    )


def _verify_signature_if_requested(args: argparse.Namespace, path: Path) -> None:
    if not signature_requested(args):
        return
    signature = signature_result(args, path)
    if not signature.ok:
        console.print(
            f"[red]SIGNATURE FAILED[/] state={_terminal(signature.state)}: "
            f"{_terminal(signature.reason)}"
        )
        raise SystemExit(1)
    tofu = (
        " [yellow](TOFU — self-asserted key, not verified)[/]" if "tofu" in signature.state else ""
    )
    console.print(
        f"[green]SIGNATURE OK[/] alg={_terminal(signature.algorithm)} "
        f"key_id={_terminal(signature.key_id or '-')} "
        f"signer={_terminal(signature.signer or '-')}{tofu}"
    )


def _refuse_ignored_sign_flags(args: argparse.Namespace) -> None:
    """Refuse key and destination flags the chosen signing mode cannot honour."""
    if not args.save:
        # Signing in place rewrites args.run_id itself, so there is no separate
        # destination to guard: --overwrite would be accepted and never consulted.
        refuse_unhonoured(
            args,
            ("overwrite",),
            mode="without --save",
            hint="Signing in place always rewrites the source artifact.",
        )
    if args.algorithm == "ed25519":
        refuse_unhonoured(
            args,
            ("key_env", "key_file"),
            mode="with --algorithm ed25519",
            hint="Ed25519 signing reads only --ed25519-key-file.",
        )
        return
    refuse_unhonoured(
        args,
        ("ed25519_key_file",),
        mode=f"with --algorithm {args.algorithm}",
        hint="Pass --algorithm ed25519 to sign with that key.",
    )
    refuse_conflict(
        args, ("key_env", "key_file"), hint="Both name an HMAC key; pass the one you mean."
    )


def cmd_sign(args: argparse.Namespace) -> None:
    _refuse_ignored_sign_flags(args)
    path = _find_run(args.run_id)
    if not path:
        console.print(f"[red]Run not found: {_terminal(args.run_id)}[/]")
        raise SystemExit(1)
    integrity = Run.verify_integrity(path)
    if not integrity.ok and not args.force:
        console.print(f"[red]Refusing to sign: {_terminal(integrity.reason)}. Pass --force.[/]")
        raise SystemExit(1)
    try:
        if args.algorithm == "ed25519":
            if not args.ed25519_key_file:
                raise SignatureError("--ed25519-key-file is required for ed25519")
            key = ed25519_private_from_file(args.ed25519_key_file)
        elif args.key_env:
            key = hmac_key_from_env(args.key_env)
        elif args.key_file:
            key = hmac_key_from_file(args.key_file)
        else:
            raise SignatureError("provide --key-env or --key-file for HMAC signing")
        run = Run.load(path)
        output = Path(args.save) if args.save else path
        # Guarded by --overwrite, never --force: --force waives the integrity
        # refusal above, so reusing it here would let "yes, replace that file"
        # silently also mean "yes, sign this tampered artifact".
        if args.save and output.exists() and not args.overwrite:
            raise SignatureError(f"{output} already exists; pass --overwrite to replace it")
        run.save(
            output,
            sign_key=key,
            sign_algorithm=args.algorithm,
            key_id=args.key_id,
            signer=args.signer,
        )
    # OSError/ValueError/RecursionError too: an unreadable key file, and an artifact
    # --force waved past the integrity refusal, both reach here, and both used to end
    # in a traceback.  `tine migrate` already reports the same failures as messages.
    except (OSError, RecursionError, SignatureError, ValueError) as exc:
        console.print(f"[red]Signing failed:[/] {_terminal(exc)}")
        raise SystemExit(1) from exc
    console.print(
        f"[{BRAND}]# Signed[/] {_terminal(short_id(run.id))} "
        f"alg={_terminal(args.algorithm)} key_id={_terminal(args.key_id or '-')}"
    )


def cmd_keygen(args: argparse.Namespace) -> None:
    if not args.out and not args.pub:
        # Both halves go to stdout, so there is no file for --force to replace: the
        # flag was accepted and never consulted.  Same shape as `sign --overwrite`
        # without --save.
        refuse_unhonoured(
            args,
            ("force",),
            mode="without --out or --pub",
            hint="Keys printed to stdout replace no file; pass --out PATH to write one.",
        )
    try:
        seed, public = generate_ed25519()
    except SignatureError as exc:
        console.print(f"[red]{_terminal(exc)}[/]")
        raise SystemExit(1) from exc
    target_pub = args.pub or (args.out + ".pub" if args.out else None)
    if args.out and target_pub and Path(args.out) == Path(target_pub):
        # Writing the seed and then the public key to one path leaves only the
        # public key: the private half is destroyed and the command still exits 0.
        console.print("[red]--out and --pub must name different files.[/]")
        raise SystemExit(1)
    # Silently overwriting a private key destroys the only copy of a signing
    # identity, and every artifact it signed becomes unverifiable.
    for existing in (args.out, target_pub):
        if existing and Path(existing).exists() and not args.force:
            console.print(f"[red]{_terminal(existing)} already exists; pass --force.[/]")
            raise SystemExit(1)
    if args.out:
        atomic_write_text(args.out, seed + "\n", fsync=True, mode=0o600)
    else:
        console.print(f"private (seed hex): {seed}")
    target = target_pub
    if target:
        atomic_write_text(target, public + "\n")
    else:
        console.print(f"public (hex): {public}")
