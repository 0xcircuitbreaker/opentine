"""``python tine-verify.pyz PATH [--pubkey KEY.pub | --key-file KEY] [--strict]``.

PATH is a ``.tine`` file or an evidence folder (one holding ``MANIFEST.sha256``).
Prints one ``tine-pyz-verify/1`` JSON report and exits 0 on a pass, 1 on a
fail and 2 on a usage error. Before anything is read, every socket connect and
name lookup in this process is made to raise: offline verification never
touches the network (ROADMAP §2), whatever the host allows.
"""

from __future__ import annotations

import argparse
import json
import socket
import sys
from pathlib import Path
from typing import Any

from . import _artifact, _evidence

SCHEMA = "tine-pyz-verify/1"
MAX_KEY_BYTES = 1 << 20


class NetworkRefused(OSError):
    """A network call inside the offline verifier."""


def _refuse(*_args: Any, **_kwargs: Any) -> Any:
    raise NetworkRefused("tine-verify.pyz is offline: network access is refused")


def no_network() -> None:
    """Make every connect and lookup in this process raise :class:`NetworkRefused`."""
    for name in ("getaddrinfo", "gethostbyname", "gethostbyname_ex", "create_connection"):
        setattr(socket, name, _refuse)
    socket.socket.connect = _refuse  # type: ignore[method-assign]
    socket.socket.connect_ex = _refuse  # type: ignore[method-assign]


def _key_bytes(path: str) -> bytes:
    with Path(path).open("rb") as handle:
        raw = handle.read(MAX_KEY_BYTES + 1)
    if len(raw) > MAX_KEY_BYTES:
        raise ValueError("key file exceeds the 1 MiB limit")
    return raw[:-1] if raw.endswith(b"\n") else raw


def public_key(path: str) -> bytes:
    """A raw 32-byte or 64-hex Ed25519 public key file (``tine keygen``'s ``.pub``)."""
    raw = _key_bytes(path)
    try:
        text = raw.decode("ascii").strip()
    except UnicodeDecodeError:
        text = ""
    if len(text) == 64:
        return bytes.fromhex(text)
    if len(raw) == 32:
        return raw
    raise ValueError("--pubkey must hold a raw 32-byte or 64-hex Ed25519 public key")


def verify_file(
    path: Path, *, hmac_key: bytes | None = None, pubkey: bytes | None = None, strict: bool = False
) -> dict[str, Any]:
    digest, data = _artifact.digest_check(path)
    ok = digest["outcome"] == "pass"
    signature = _artifact.signature_check(data, ok, hmac_key=hmac_key, public_key=pubkey)
    return report("artifact", path, [digest, signature], strict)


def report(mode: str, path: Path, checks: list[dict[str, Any]], strict: bool, **extra: Any) -> Any:
    failed = any(c["outcome"] == "fail" for c in checks)
    missing = any(c["outcome"] == "unavailable-offline" and c.get("required") for c in checks)
    ok = not failed and not (strict and missing)
    return {
        "schema": SCHEMA,
        "mode": mode,
        "path": str(path),
        "strict": strict,
        "verdict": "pass" if ok else "fail",
        "ok": ok,
        "checks": checks,
        **extra,
    }


def main(argv: list[str] | None = None) -> int:
    no_network()
    parser = argparse.ArgumentParser(
        prog="tine-verify.pyz", description="Verify .tine files and evidence folders offline."
    )
    parser.add_argument("path", help="a .tine file or an evidence folder")
    keys = parser.add_mutually_exclusive_group()
    keys.add_argument("--pubkey", metavar="FILE", help="trusted Ed25519 public key")
    keys.add_argument("--key-file", metavar="FILE", help="shared HMAC-SHA256 secret")
    parser.add_argument(
        "--strict", action="store_true", help="fail if a required check cannot run offline"
    )
    args = parser.parse_args(argv)
    try:
        pubkey = public_key(args.pubkey) if args.pubkey else None
        secret = _key_bytes(args.key_file) if args.key_file else None
    except (OSError, ValueError) as exc:
        parser.error(f"cannot read the key: {exc}")
    path = Path(args.path)

    def one(item: Path) -> dict[str, Any]:
        return verify_file(item, hmac_key=secret, pubkey=pubkey, strict=args.strict)

    if path.is_dir():
        if not (path / "MANIFEST.sha256").is_file():
            parser.error(f"{path} is a directory but not an evidence folder (no MANIFEST.sha256)")
        found = _evidence.verify_evidence(path, one)
        result = report("evidence", path, found["checks"], args.strict, runs=found["runs"])
    else:
        result = one(path)
    sys.stdout.write(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return 0 if result["ok"] else 1


__all__ = ["main", "no_network", "public_key", "verify_file"]
