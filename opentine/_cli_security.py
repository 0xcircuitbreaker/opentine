"""Integrity verification, signing, and key generation commands."""

from __future__ import annotations

import argparse
from pathlib import Path

from opentine._canon import atomic_write_text
from opentine._cli_common import BRAND, _find_run, _terminal, console
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
    path = _find_run(args.run_id)
    if not path:
        result = Run.verify_integrity(args.run_id)
        console.print(f"[red]FAILED[/] {_terminal(args.run_id)}: {_terminal(result.reason)}")
        raise SystemExit(1)
    result = Run.verify_integrity(path)
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


def _verify_signature_if_requested(args: argparse.Namespace, path: Path) -> None:
    key_env = getattr(args, "key_env", None)
    key_file = getattr(args, "key_file", None)
    public_path = getattr(args, "pubkey", None)
    required = bool(key_env or key_file or public_path or getattr(args, "require_signature", False))
    if not required:
        return
    try:
        hmac_key = hmac_key_from_env(key_env) if key_env else None
        if key_file:
            hmac_key = hmac_key_from_file(key_file)
        public = ed25519_public_from_file(public_path) if public_path else None
    except SignatureError as exc:
        console.print(f"[red]SIGNATURE FAILED[/] {_terminal(exc)}")
        raise SystemExit(1) from exc
    signature = Run.verify_signature(
        path,
        hmac_key=hmac_key,
        public_key=public,
        trust_embedded=getattr(args, "trust_embedded_key", False),
    )
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


def cmd_sign(args: argparse.Namespace) -> None:
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
    except SignatureError as exc:
        console.print(f"[red]Signing failed:[/] {_terminal(exc)}")
        raise SystemExit(1) from exc
    console.print(
        f"[{BRAND}]# Signed[/] {_terminal(short_id(run.id))} "
        f"alg={_terminal(args.algorithm)} key_id={_terminal(args.key_id or '-')}"
    )


def cmd_keygen(args: argparse.Namespace) -> None:
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
