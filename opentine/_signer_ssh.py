"""``ssh-agent:FINGERPRINT``: sign with an Ed25519 key an ``ssh-agent`` holds.

Speaks the agent protocol (draft-miller-ssh-agent) directly over
``SSH_AUTH_SOCK`` -- a Unix socket, or on Windows the OpenSSH named pipe -- so
no SSH library is needed. FINGERPRINT is ``SHA256:<base64>`` as ``ssh-add -l``
prints it, opentine's ``sha256:<hex>`` of the raw key, or ``*`` for the only
Ed25519 key the agent has. Ed25519 agent signatures are plain RFC 8032
signatures over the message, so they verify like any other.
"""

from __future__ import annotations

import base64
import hashlib
import os
import socket
import struct
from typing import Any

from opentine._signer import BaseSigner
from opentine._signing_keys import SignatureError

REQUEST_IDENTITIES, IDENTITIES_ANSWER = 11, 12
SIGN_REQUEST, SIGN_RESPONSE = 13, 14
KEY_TYPE = b"ssh-ed25519"
MAX_REPLY = 256 * 1024


def _string(value: bytes) -> bytes:
    return struct.pack(">I", len(value)) + value


def _read_string(buf: bytes, at: int) -> tuple[bytes, int]:
    if at + 4 > len(buf):
        raise SignatureError("ssh-agent reply is truncated")
    (size,) = struct.unpack_from(">I", buf, at)
    end = at + 4 + size
    if end > len(buf):
        raise SignatureError("ssh-agent reply is truncated")
    return buf[at + 4 : end], end


class _Channel:
    def __init__(self, path: str) -> None:
        if path.startswith("\\\\.\\pipe\\"):
            self._file: Any = open(path, "r+b", buffering=0)  # noqa: SIM115
            self._sock = None
        else:
            if not hasattr(socket, "AF_UNIX"):
                raise SignatureError("ssh-agent needs a Unix socket or an OpenSSH named pipe")
            self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self._sock.settimeout(30)
            self._sock.connect(path)

    def _recv(self, size: int) -> bytes:
        out = b""
        while len(out) < size:
            part = (self._sock.recv if self._sock else self._file.read)(size - len(out))
            if not part:
                raise SignatureError("ssh-agent closed the connection")
            out += part
        return out

    def call(self, payload: bytes) -> bytes:
        message = struct.pack(">I", len(payload)) + payload
        (self._sock.sendall if self._sock else self._file.write)(message)
        (size,) = struct.unpack(">I", self._recv(4))
        if not 0 < size <= MAX_REPLY:
            raise SignatureError("ssh-agent reply has a bad length")
        return self._recv(size)

    def close(self) -> None:
        (self._sock or self._file).close()


def _socket_path(sock: str | None) -> str:
    path = sock or os.environ.get("SSH_AUTH_SOCK")
    if not path:
        raise SignatureError("ssh-agent: SSH_AUTH_SOCK is not set")
    return path


def identities(sock: str | None = None) -> list[tuple[bytes, bytes, str]]:
    """``(key blob, raw public key, comment)`` of every Ed25519 key in the agent."""
    channel = _Channel(_socket_path(sock))
    try:
        reply = channel.call(bytes([REQUEST_IDENTITIES]))
    except OSError as exc:
        raise SignatureError(f"ssh-agent: {exc}") from exc
    finally:
        channel.close()
    if reply[:1] != bytes([IDENTITIES_ANSWER]) or len(reply) < 5:
        raise SignatureError("ssh-agent refused to list its keys")
    (count,) = struct.unpack_from(">I", reply, 1)
    at, found = 5, []
    for _ in range(min(count, 1024)):
        blob, at = _read_string(reply, at)
        comment, at = _read_string(reply, at)
        kind, inner = _read_string(blob, 0)
        if kind == KEY_TYPE:
            raw, _ = _read_string(blob, inner)
            if len(raw) == 32:
                found.append((blob, raw, comment.decode("utf-8", "replace")))
    return found


def ssh_fingerprint(blob: bytes) -> str:
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


def _matches(wanted: str, blob: bytes, raw: bytes) -> bool:
    from opentine._signing_pins import key_fingerprint

    return wanted in (ssh_fingerprint(blob), key_fingerprint(raw), raw.hex())


class AgentSigner(BaseSigner):
    def __init__(self, fingerprint: str, sock: str | None = None) -> None:
        self._sock = sock
        keys = identities(sock)
        chosen = (
            keys if fingerprint == "*" else [k for k in keys if _matches(fingerprint, k[0], k[1])]
        )
        if len(chosen) != 1:
            raise SignatureError(
                f"ssh-agent holds {len(chosen)} Ed25519 keys matching {fingerprint!r}; "
                "name one by its SHA256: fingerprint (ssh-add -l)"
            )
        self._blob, self._raw, _ = chosen[0]
        self.uri = f"ssh-agent:{ssh_fingerprint(self._blob)}"

    @property
    def public_key(self) -> bytes:
        return self._raw

    def sign(self, message: bytes) -> bytes:
        channel = _Channel(_socket_path(self._sock))
        try:
            reply = channel.call(
                bytes([SIGN_REQUEST]) + _string(self._blob) + _string(message) + b"\0\0\0\0"
            )
        except OSError as exc:
            raise SignatureError(f"ssh-agent: {exc}") from exc
        finally:
            channel.close()
        if reply[:1] != bytes([SIGN_RESPONSE]):
            raise SignatureError("ssh-agent refused to sign (is the key still loaded?)")
        blob, _ = _read_string(reply, 1)
        kind, at = _read_string(blob, 0)
        signature, _ = _read_string(blob, at)
        if kind != KEY_TYPE or len(signature) != 64:
            raise SignatureError("ssh-agent returned a non-Ed25519 signature")
        return signature


__all__ = ["AgentSigner", "identities", "ssh_fingerprint"]
