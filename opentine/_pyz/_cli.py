"""``python tine-verify.pyz PATH [--pubkey KEY.pub | --key-file KEY] [--strict]``.

PATH is a ``.tine`` file, an evidence folder (one holding ``MANIFEST.sha256``),
or an eval folder / ``.jsonl`` of ``tine-eval-verdict/1`` verdicts (0.45), or a
redaction report, tombstone or redacted-copy record (0.45.1, 0.46), or a project
manifest, its history or a mirror state (0.46.1; a mirror state never passes).
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

from . import _artifact, _evalv, _evidence, _mergerec, _projfile, _records, _redactr

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
    """A raw or hex public key: Ed25519 (``tine keygen``'s ``.pub``), ML-DSA-65 or composite."""
    raw = _key_bytes(path)
    try:
        text = raw.decode("ascii").strip()
    except UnicodeDecodeError:
        text = ""
    if len(text) in (64, 3904, 3968):
        return bytes.fromhex(text)
    if len(raw) in (32, 1952, 1984):
        return raw
    raise ValueError("--pubkey must hold an Ed25519, ml-dsa-65 or ed25519+ml-dsa-65 public key")


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
    parser.add_argument("path", help="a .tine file, an evidence folder or eval verdicts")
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

    if _projfile.kind(path):  # 0.46.1: a project manifest (or history) or a mirror state
        checks, verdict = _projfile.verify(path, pubkey)
        result = report(_projfile.kind(path) or "project", path, checks, args.strict)
        result.update({"verdict": verdict} if verdict else {})  # a host statement never passes
    elif _records.is_record(path):  # 0.46: a tombstone or a redacted-copy record
        checks = _records.verify_record(path, secret, pubkey)
        result = report(_records.mode(path), path, checks, args.strict)
    elif _mergerec.is_record(path):  # 0.47: a merge attestation or a merge approval
        checks = _mergerec.verify_record(path, secret, pubkey)
        result = report(_mergerec.mode(path), path, checks, args.strict)
    elif _redactr.is_report(path):
        checks = _redactr.verify_report(path, secret, pubkey)
        result = report("redaction-report", path, checks, args.strict)
    elif _evalv.is_eval(path):
        result = report("eval", path, _evalv.verify_eval(path, pubkey), args.strict)
    elif path.is_dir():
        if not (path / "MANIFEST.sha256").is_file():
            parser.error(f"{path} is a directory but not an evidence folder (no MANIFEST.sha256)")
        found = _evidence.verify_evidence(path, one)
        result = report("evidence", path, found["checks"], args.strict, runs=found["runs"])
    else:
        result = one(path)
    sys.stdout.write(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return 0 if result["ok"] else 1


__all__ = ["main", "no_network", "public_key", "verify_file"]
