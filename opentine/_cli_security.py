"""Integrity verification, signing, and key generation commands."""

from __future__ import annotations

import argparse
from pathlib import Path

from opentine._cli_common import BRAND, _find_run, _terminal, console
from opentine._cli_flags import KEY_MATERIAL_FLAGS, refuse_conflict, refuse_unhonoured
from opentine._cli_keygen import cmd_keygen
from opentine._cli_verify_report import emit_verify, signature_block, unchecked_signature
from opentine._key_hygiene import ed25519_private, hmac_key
from opentine._signing_pins import apply_pins, normalize_pins, used_key_fingerprint
from opentine.core import Run, short_id
from opentine.signing import SignatureError, ed25519_public_from_file


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
        signature, fingerprint = signature_result(args, path) if armed else (None, None)
        unchecked = unchecked_signature(path) if result.ok and not armed else None
        emit_verify(path, result, signature, fingerprint=fingerprint, unchecked=unchecked)
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
    if not signature_requested(args) and (unchecked := unchecked_signature(path)) is not None:
        # An OK beside a signed artifact read as "authentic" though nothing was checked.
        console.print(
            f"[yellow]signature present but NOT checked[/] alg={_terminal(unchecked.algorithm)} "
            f"signer={_terminal(unchecked.signer or '-')}: pass --pubkey, --key-file, "
            "--key-env or --pin to check it"
        )
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
        or getattr(args, "pin", None)
    )


def signature_result(args: argparse.Namespace, path: Path):
    """Run the armed check: ``(verdict, key fingerprint)``; exit 1 on unreadable keys.

    ``--pin`` alone means "trust the embedded key if it is one of these"; it never
    combines with an HMAC key, which has no fingerprint to pin.
    """
    key_env = getattr(args, "key_env", None)
    key_file = getattr(args, "key_file", None)
    public_path = getattr(args, "pubkey", None)
    if getattr(args, "pin", None) and (key_env or key_file):
        flag = "--key-env" if key_env else "--key-file"
        console.print(f"[red]--pin and {flag} cannot be combined:[/] a pin names an Ed25519 key.")
        raise SystemExit(1)
    try:
        pins = normalize_pins(getattr(args, "pin", None))
        secret = hmac_key(key_env, key_file) if key_env or key_file else None
        public = ed25519_public_from_file(public_path) if public_path else None
    # OSError as well as SignatureError: a --key-file/--pubkey path that is missing,
    # a directory, or unreadable came out as an interpreter traceback, which is the
    # single most likely way to mistype one of these options.
    except (OSError, SignatureError) as exc:
        console.print(f"[red]SIGNATURE FAILED[/] cannot read the key: {_terminal(exc)}")
        raise SystemExit(1) from exc
    trust_embedded = getattr(args, "trust_embedded_key", False) or bool(pins and not public)
    result = Run.verify_signature(
        path, hmac_key=secret, public_key=public, trust_embedded=trust_embedded
    )
    fingerprint = used_key_fingerprint(signature_block(path), public)
    return apply_pins(result, fingerprint, pins), fingerprint


def _verify_signature_if_requested(args: argparse.Namespace, path: Path) -> None:
    if not signature_requested(args):
        return
    signature, fingerprint = signature_result(args, path)
    if not signature.ok:
        console.print(
            f"[red]SIGNATURE FAILED[/] state={_terminal(signature.state)}: "
            f"{_terminal(signature.reason)}"
        )
        raise SystemExit(1)
    tofu = (
        " [yellow](TOFU — self-asserted key, not verified)[/]" if "tofu" in signature.state else ""
    )
    key = f" key={_terminal(fingerprint)}" if fingerprint else ""
    console.print(
        f"[green]SIGNATURE OK[/] alg={_terminal(signature.algorithm)} "
        f"key_id={_terminal(signature.key_id or '-')} "
        f"signer={_terminal(signature.signer or '-')}{key}{tofu}"
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
            key = ed25519_private(args.ed25519_key_file)
        elif args.key_env or args.key_file:
            key = hmac_key(args.key_env, args.key_file)
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


__all__ = ["cmd_keygen", "cmd_sign", "cmd_verify", "signature_requested", "signature_result"]
