"""Signed-note checkpoints (https://c2sp.org/signed-note) and appends for ``_tlog``.

The checkpoint body is ``<origin>\\n<size>\\n<base64 root>\\n``; each signature
line is ``— <key name> <base64(key id || Ed25519 signature)>``, where the key id
is the first four bytes of ``SHA-256(name || 0x0A || 0x01 || public key)``. A log
signs with its own Ed25519 key (``key``, mode 0600, from the shared signing-key
code); ``vkey`` holds the verifier key in signed-note's ``name+hash+key`` form, so
a reader can pin it out of band (``tine op verify --vkey``). Verification is
local file reads only: it never touches the network.
"""

from __future__ import annotations

import base64
import hashlib
import os
from collections.abc import Callable
from pathlib import Path

from opentine._signing_keys import (
    coerce_ed25519_public,
    ed25519_private_from_file,
    generate_ed25519,
)
from opentine.repository import _tlog
from opentine.repository._paths import atomic_bytes, durable_directory

_DASH = "— "


def _key_id(name: str, public: bytes) -> bytes:
    return hashlib.sha256(name.encode() + b"\n\x01" + public).digest()[:4]


def vkey_for(name: str, public: bytes) -> str:
    encoded = base64.b64encode(b"\x01" + public).decode()
    return f"{name}+{_key_id(name, public).hex()}+{encoded}"


def parse_vkey(vkey: str) -> tuple[str, bytes]:
    try:
        name, key_hash, encoded = vkey.strip().split("+", 2)
        raw = base64.b64decode(encoded, validate=True)
    except ValueError as exc:
        raise _tlog.LogError("verifier key is not name+hash+key") from exc
    if len(raw) != 33 or raw[0] != 1 or _key_id(name, raw[1:]).hex() != key_hash:
        raise _tlog.LogError("verifier key is not an Ed25519 signed-note key")
    return name, raw[1:]


def _signer(root: Path, origin: str):
    key = root / "key"
    if not key.exists():
        durable_directory(root)
        seed, public = generate_ed25519()
        fd = os.open(key, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w", encoding="ascii") as handle:
            handle.write(seed + "\n")
        atomic_bytes(root / "vkey", (vkey_for(origin, bytes.fromhex(public)) + "\n").encode())
    return ed25519_private_from_file(key)


def stored_vkey(root: Path) -> str:
    try:
        return (root / "vkey").read_text("ascii").strip()
    except (FileNotFoundError, UnicodeDecodeError) as exc:
        raise _tlog.LogError("log has no verifier key") from exc


def sign_checkpoint(private, origin: str, size: int, tree_root: bytes) -> bytes:
    body = f"{origin}\n{size}\n{base64.b64encode(tree_root).decode()}\n".encode()
    public = private.public_key().public_bytes_raw()
    signature = base64.b64encode(_key_id(origin, public) + private.sign(body)).decode()
    return body + f"\n{_DASH}{origin} {signature}\n".encode()


def open_checkpoint(note: bytes, vkey: str) -> tuple[str, int, bytes]:
    """``(origin, size, root)`` of a checkpoint the verifier key signed, or LogError."""
    name, public = parse_vkey(vkey)
    try:
        text = note.decode("utf-8")
        body, signatures = text.split("\n\n", 1)
        origin, size_text, root_text = body.split("\n")
        size, tree_root = int(size_text), base64.b64decode(root_text, validate=True)
    except ValueError as exc:
        raise _tlog.LogError("checkpoint is not a signed note") from exc
    if str(size) != size_text or len(tree_root) != 32 or origin != name:
        raise _tlog.LogError("checkpoint is malformed or names another log")
    verifier = coerce_ed25519_public(public.hex())
    for line in signatures.splitlines():
        if not line.startswith(_DASH) or line[len(_DASH) :].split(" ")[0] != name:
            continue
        try:
            raw = base64.b64decode(line.rsplit(" ", 1)[1], validate=True)
            if raw[:4] == _key_id(name, public):
                verifier.verify(raw[4:], (body + "\n").encode())
                return origin, size, tree_root
        except Exception:  # noqa: BLE001 - a bad signature line is just not a signature
            continue
    raise _tlog.LogError("checkpoint signature does not verify")


def verify_log(root: Path, origin: str, vkey: str | None = None) -> list[bytes]:
    """Every entry of a log whose tiles and signed checkpoint all agree, or LogError."""
    try:
        note = (root / "checkpoint").read_bytes()
    except FileNotFoundError:
        return []
    _, size, tree_root = open_checkpoint(note, vkey or stored_vkey(root))
    if _origin_of(note) != origin:
        raise _tlog.LogError("checkpoint names another log")
    entries = _tlog.read_entries(root, size)
    leaves = [_tlog.leaf_hash(e) for e in entries]
    if _tlog.merkle_root(leaves) != tree_root:
        raise _tlog.LogError("log entries do not match the signed checkpoint root")
    _tlog.check_tiles(root, leaves)
    return entries


def _origin_of(note: bytes) -> str:
    return note.split(b"\n", 1)[0].decode("utf-8", "replace")


def append(root: Path, origin: str, make: Callable[[list[bytes]], bytes]) -> int:
    """Append ``make(entries)`` to the verified log, under its lock; return its index."""
    with _tlog.log_lock(root):
        private = _signer(root, origin)
        entries = verify_log(root, origin)
        old_size = len(entries)
        entry = make(entries)
        if len(entry) > _tlog.MAX_ENTRY_BYTES:
            raise _tlog.LogError("log entry exceeds 65535 bytes")
        entries.append(entry)
        _tlog.write_tiles(root, entries, old_size)
        tree_root = _tlog.merkle_root([_tlog.leaf_hash(e) for e in entries])
        atomic_bytes(root / "checkpoint", sign_checkpoint(private, origin, len(entries), tree_root))
        return old_size
