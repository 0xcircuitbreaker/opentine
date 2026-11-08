"""``tine push --dry-run`` / ``--outgoing`` and ``--manifest`` (see ``_push_preview``)."""

from __future__ import annotations

import argparse
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

from opentine import _push_preview
from opentine._codec_io import atomic_write_bytes
from opentine._signing_keys import ed25519_private_from_file, hmac_key_from_file


def add_push_parser(subparsers, remote_args: Callable[[argparse.ArgumentParser], None]) -> None:
    push = subparsers.add_parser("push", help="Push a pack and CAS-update a remote ref")
    remote_args(push)
    push.add_argument("--ref", default="heads/main")
    push.add_argument("--all", action="store_true", help="Push every heads/* ref")
    push.add_argument("--remote-ref")
    push.add_argument("--force", action="store_true", help="Non-fast-forward (admin)")
    push.add_argument("--repo", default=".")
    push.add_argument(
        "--dry-run",
        "--outgoing",
        dest="dry_run",
        action="store_true",
        help="List the refs, objects and runs a push would send; no network access",
    )
    push.add_argument(
        "--manifest", metavar="PATH", help="Write the canonical-JSON push manifest to PATH"
    )
    push.add_argument(
        "--allow-unredacted",
        metavar="REASON",
        help="Push even if outgoing objects fail the redaction scan; REASON goes in the op log",
    )
    keys = push.add_mutually_exclusive_group()
    keys.add_argument("--key-file", metavar="PATH", help="Sign the manifest (HMAC key file)")
    keys.add_argument("--ed25519-key-file", metavar="PATH", help="Sign the manifest (Ed25519)")
    push.add_argument("--key-id", help="Key id recorded in the manifest signature")


def manifest(repo: Any, args: argparse.Namespace, tracking: str, refs: list[str]) -> dict:
    """The (signed, with a key flag) manifest; written to ``--manifest`` when given."""
    remote_ref = None if getattr(args, "all", False) else args.remote_ref
    body = _push_preview.outgoing(repo, args.remote, tracking, refs, remote_ref)
    if getattr(args, "key_file", None):
        body = _push_preview.sign(
            body, hmac_key_from_file(args.key_file), algorithm="hmac-sha256", key_id=args.key_id
        )
    elif getattr(args, "ed25519_key_file", None):
        key = ed25519_private_from_file(args.ed25519_key_file)
        body = _push_preview.sign(body, key, algorithm="ed25519", key_id=args.key_id)
    if getattr(args, "manifest", None):
        atomic_write_bytes(Path(args.manifest), _push_preview.encode(body))
    return body


def wants_manifest(args: argparse.Namespace) -> bool:
    signing = getattr(args, "key_file", None) or getattr(args, "ed25519_key_file", None)
    if getattr(args, "key_id", None) and not signing:
        raise ValueError("--key-id needs --key-file or --ed25519-key-file")
    if (signing or getattr(args, "key_id", None)) and not getattr(args, "manifest", None):
        if not getattr(args, "dry_run", False):
            raise ValueError("a manifest key flag needs --manifest PATH or --dry-run")
    return bool(getattr(args, "dry_run", False) or getattr(args, "manifest", None))


def emit_preview(body: dict) -> None:
    print(json.dumps(body, indent=2))


__all__ = ["add_push_parser", "emit_preview", "manifest", "wants_manifest"]
