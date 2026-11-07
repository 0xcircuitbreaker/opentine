"""C2SP tlog-cosignature/v1 witness cosignatures on signed-note checkpoints.

A witness signs, with Ed25519, the message ``cosignature/v1\\ntime <T>\\n``
followed by the checkpoint body (origin, size, root and any extension lines),
where ``T`` is POSIX seconds in ASCII decimal. Its note signature line is
``— <name> base64(key id || uint64be(T) || signature)`` and its key id the first
four bytes of ``SHA-256(name || 0x0A || 0x04 || public key)`` -- signature type
``0x04``, so a cosignature can never be mistaken for a log (``0x01``) signature.
Witness verifier keys use signed-note's ``name+hash+base64(0x04 || key)`` form.
"""

from __future__ import annotations

import base64
import hashlib
import time

from opentine.repository._tlog import LogError

COSIGNATURE_TYPE = 0x04
_DASH = "— "
MAX_NOTE_BYTES = 1 << 16
MAX_SIGNATURE_LINES = 100


def key_id(name: str, public: bytes) -> bytes:
    return hashlib.sha256(name.encode() + b"\n" + bytes([COSIGNATURE_TYPE]) + public).digest()[:4]


def witness_vkey(name: str, public: bytes) -> str:
    encoded = base64.b64encode(bytes([COSIGNATURE_TYPE]) + public).decode()
    return f"{name}+{key_id(name, public).hex()}+{encoded}"


def parse_witness_vkey(vkey: str) -> tuple[str, bytes]:
    try:
        name, hint, encoded = vkey.strip().split("+", 2)
        raw = base64.b64decode(encoded, validate=True)
    except ValueError as exc:
        raise LogError("witness key is not name+hash+key") from exc
    if not name or any(c in name for c in " +\n") or len(raw) != 33:
        raise LogError("witness key is malformed")
    if raw[0] != COSIGNATURE_TYPE or key_id(name, raw[1:]).hex() != hint:
        raise LogError("witness key is not an Ed25519 cosignature/v1 key")
    return name, raw[1:]


def split_note(note: bytes) -> tuple[str, list[str]]:
    """``(body, signature lines)``: the body ends with its final newline."""
    if len(note) > MAX_NOTE_BYTES:
        raise LogError("checkpoint note is too large")
    try:
        text = note.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise LogError("checkpoint note is not UTF-8") from exc
    body, sep, signatures = text.partition("\n\n")
    if not sep:
        raise LogError("checkpoint is not a signed note")
    lines = [line for line in signatures.split("\n") if line]
    if len(lines) > MAX_SIGNATURE_LINES:
        raise LogError("checkpoint carries too many signatures")
    return body + "\n", lines


def message(body: str, timestamp: int) -> bytes:
    return f"cosignature/v1\ntime {timestamp}\n{body}".encode()


def cosign(note: bytes, private, name: str, timestamp: int | None = None) -> bytes:
    """``note`` with this witness's cosignature line appended."""
    body, _ = split_note(note)
    stamp = int(time.time()) if timestamp is None else timestamp
    public = private.public_key().public_bytes_raw()
    raw = key_id(name, public) + stamp.to_bytes(8, "big") + private.sign(message(body, stamp))
    line = f"{_DASH}{name} {base64.b64encode(raw).decode()}\n"
    return (note if note.endswith(b"\n") else note + b"\n") + line.encode()


def cosigners(note: bytes, vkeys: list[str]) -> dict[str, int]:
    """``{witness name: timestamp}`` of every pinned witness whose cosignature verifies."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    body, lines = split_note(note)
    keys = {}
    for vkey in vkeys:
        name, public = parse_witness_vkey(vkey)
        keys[(name, key_id(name, public))] = public
    found: dict[str, int] = {}
    for line in lines:
        if not line.startswith(_DASH):
            continue
        name, _, encoded = line[len(_DASH) :].partition(" ")
        try:
            raw = base64.b64decode(encoded, validate=True)
        except ValueError:
            continue
        public = keys.get((name, raw[:4]))
        if public is None or len(raw) != 76:
            continue
        stamp = int.from_bytes(raw[4:12], "big")
        try:
            Ed25519PublicKey.from_public_bytes(public).verify(raw[12:], message(body, stamp))
        except InvalidSignature:
            continue
        found[name] = stamp
    return found


def parse_quorum(text: str) -> tuple[int, int]:
    """``"N-of-M"`` -> ``(N, M)`` with ``1 <= N <= M``."""
    try:
        need, _, total = text.lower().partition("-of-")
        n, m = int(need), int(total)
    except ValueError as exc:
        raise ValueError(f"--witnesses takes N-of-M, not {text!r}") from exc
    if not 1 <= n <= m:
        raise ValueError(f"--witnesses {text}: need 1 <= N <= M")
    return n, m


def check_quorum(note: bytes, vkeys: list[str], need: int, total: int) -> dict[str, int]:
    """The verifying cosigners; LogError unless at least ``need`` of ``total`` pinned keys."""
    names = [parse_witness_vkey(v)[0] for v in vkeys]
    if len(set(names)) != len(names) or len(vkeys) != total:
        raise LogError(f"--witnesses names {total} witnesses but {len(set(names))} keys are pinned")
    found = cosigners(note, vkeys)
    if len(found) < need:
        raise LogError(f"witness quorum not met: {len(found)} of {need}-of-{total} cosigned")
    return found
