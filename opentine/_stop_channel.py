"""The fleet stop channel: an append-only transparency log of stop and continue proofs.

A channel is a directory (shared by every repository of a fleet, local or on a
mounted share) holding one tiled Merkle log (:mod:`opentine.repository._tlog`)
whose origin is ``opentine-stop/<fleet>``. Each entry is the canonical JSON of
``{"kind": "stop"|"continue", "attestation": OID, "payload": PAYLOAD}``: the
signed attestation payload itself (claim conventions ``opentine.fleet-stop/1``
and ``opentine.stop-continue/1``, :mod:`opentine._stop_proof`), so a runner in
another repository verifies it without that repository.

The log key (``key``) belongs to whoever publishes stops and continues; a
runner needs only the verifier key (``vkey``), which the stop policy pins.
:func:`snapshot` verifies every entry against the signed checkpoint and that
pinned key. Anything it cannot read or verify raises :class:`ChannelError`,
which every caller treats as "the stop channel is unreachable" (fail closed).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ORIGIN_PREFIX = "opentine-stop/"
FLEET_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
KINDS = ("stop", "continue")


class ChannelError(ValueError):
    """The stop channel cannot be read or does not verify (treated as unreachable)."""


@dataclass(frozen=True)
class Snapshot:
    """A verified view of a channel: its checkpoint and its entries in log order."""

    origin: str
    size: int
    root: str
    entries: tuple[dict[str, Any], ...]
    leaves: tuple[bytes, ...]

    def checkpoint(self) -> dict[str, Any]:
        return {"origin": self.origin, "size": self.size, "root": self.root}

    def prefix_root(self, size: int) -> str:
        """The Merkle root of the first *size* entries (a checkpoint this log extends)."""
        from opentine.repository._tlog import merkle_root

        if not 0 <= size <= self.size:
            raise ChannelError(f"checkpoint size {size} is beyond the log ({self.size})")
        return merkle_root(list(self.leaves[:size])).hex()


def origin(fleet: str) -> str:
    if not isinstance(fleet, str) or not FLEET_ID.fullmatch(fleet):
        raise ValueError(f"invalid fleet id: {fleet!r} (lowercase [a-z0-9._-], at most 64)")
    return ORIGIN_PREFIX + fleet


def init(root: Path, fleet: str) -> str:
    """Create the channel at *root*, or read an existing one; its verifier key."""
    from opentine.repository import _tlog_note

    name = origin(fleet)
    root = Path(root)
    if not (root / "vkey").is_file():  # a new channel: its log key is created here, once
        root.mkdir(parents=True, exist_ok=True)
        _tlog_note._signer(root, name)
    vkey = _tlog_note.stored_vkey(root)  # an existing one is only read (the key may be elsewhere)
    if _tlog_note.parse_vkey(vkey)[0] != name:
        raise ChannelError(f"the channel at {root.as_posix()} belongs to another fleet")
    return vkey


def append(root: Path, fleet: str, kind: str, attestation: str, payload: dict) -> int:
    """Append one signed proof; its log index."""
    from opentine.kernel import canonical_json
    from opentine.repository import _tlog_note

    if kind not in KINDS:
        raise ValueError(f"unknown stop channel entry {kind!r}")
    if not (Path(root) / "key").is_file():
        raise ChannelError("this channel has no log key here: run `tine stop init` first")
    entry = canonical_json({"kind": kind, "attestation": attestation, "payload": payload})
    return _tlog_note.append(Path(root), origin(fleet), lambda _tail: entry)


def _entry(raw: bytes) -> dict[str, Any]:
    from opentine import _json_shallow

    try:
        value = _json_shallow.loads(raw)
    except ValueError as exc:
        raise ChannelError(f"a channel entry is not JSON: {exc}") from exc
    if (
        not isinstance(value, dict)
        or set(value) != {"kind", "attestation", "payload"}
        or value["kind"] not in KINDS
        or not isinstance(value["attestation"], str)
        or not isinstance(value["payload"], dict)
    ):
        raise ChannelError("a channel entry is not {kind, attestation, payload}")
    return value


def snapshot(root: Path | str, fleet: str, vkey: str) -> Snapshot:
    """Every entry of the channel, verified against its checkpoint and the pinned *vkey*."""
    from opentine.repository import _tlog, _tlog_note

    name = origin(fleet)
    root = Path(root)
    try:
        if not (root / "checkpoint").is_file():
            if not root.is_dir():
                raise ChannelError(f"stop channel {root.as_posix()} is unreachable")
            raw: list[bytes] = []
            size, tree = 0, _tlog.merkle_root([])
        else:
            _, size, tree = _tlog_note.open_checkpoint((root / "checkpoint").read_bytes(), vkey)
            raw = _tlog_note.verify_log(root, name, vkey)
    except ChannelError:
        raise
    except (OSError, ValueError) as exc:  # LogError is a ValueError
        raise ChannelError(f"stop channel {root.as_posix()}: {exc}") from exc
    if _tlog_note.parse_vkey(vkey)[0] != name:
        raise ChannelError("the pinned channel key belongs to another fleet")
    return Snapshot(name, size, tree.hex(), tuple(_entry(e) for e in raw),
                    tuple(_tlog.leaf_hash(e) for e in raw))  # fmt: skip


__all__ = ["ChannelError", "FLEET_ID", "KINDS", "ORIGIN_PREFIX", "Snapshot", "append", "init",
           "origin", "snapshot"]  # fmt: skip
