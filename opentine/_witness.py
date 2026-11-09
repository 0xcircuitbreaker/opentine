"""A checkpoint witness (X33): cosign only what is consistent with what it saw.

The witness keeps, per log origin, the last checkpoint it cosigned
(``<state>/<sha256(origin)>.checkpoint``). Given a new checkpoint it checks the
log's signature against the pinned log key, then:

* the same size: the root must be identical (a different root is a fork);
* a smaller size: refused (a rollback);
* a larger size: an RFC 9162 consistency proof from the old size must verify,
  supplied as a proof file or computed from a local tile mirror (``tiles``).

Only then does it add its ``cosignature/v1`` line and advance its state, under
a lock. Because an honest witness never cosigns two views of one log, a split
view cannot gather a quorum of honest witnesses -- ``verify --witnesses N-of-M``
is what turns that into a detection.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from opentine.repository import _tlog, _tlog_cosign, _tlog_note, _tlog_proof
from opentine.repository._paths import atomic_bytes, durable_directory


def _state(state: Path, origin: str) -> Path:
    return state / (hashlib.sha256(origin.encode()).hexdigest() + ".checkpoint")


def load_proof(path: Path) -> list[bytes]:
    data = json.loads(path.read_text("utf-8"))
    return _tlog_proof.decode(data.get("proof") if isinstance(data, dict) else data)


def consistency_from(
    old: int, size: int, *, proof: list[bytes] | None, tiles: Path | None
) -> list[bytes]:
    if proof is not None:
        return proof
    if tiles is None:
        raise _tlog.LogError("a consistency proof (--proof or --tiles) is needed to advance")
    hashes = _tlog_proof.Hashes(size, lambda rel: _tlog._read(tiles, rel))
    return _tlog_proof.consistency_proof(hashes, old, size)


def witness(
    note: bytes,
    log_vkey: str,
    private: Any,
    name: str,
    state: Path,
    *,
    proof: list[bytes] | None = None,
    tiles: Path | None = None,
    timestamp: int | None = None,
) -> dict[str, Any]:
    """Cosign ``note`` or raise LogError naming the fork or rollback.

    *private* is one key or a list of them (0.47 key rotation): each adds its
    own cosignature line, the current key first.
    """
    origin, size, root = _tlog_note.open_checkpoint(note, log_vkey)
    durable_directory(state)
    path = _state(state, origin)
    with _tlog.log_lock(state):
        old_size = 0
        if path.exists():
            _, old_size, old_root = _tlog_note.open_checkpoint(path.read_bytes(), log_vkey)
            if size < old_size:
                raise _tlog.LogError(f"rollback: {origin} went from {old_size} to {size}")
            if size == old_size:
                _tlog_proof.verify_consistency(old_size, size, old_root, root, [])
            else:
                hashes = consistency_from(old_size, size, proof=proof, tiles=tiles)
                _tlog_proof.verify_consistency(old_size, size, old_root, root, hashes)
        cosigned = note
        for key in private if isinstance(private, list | tuple) else [private]:
            cosigned = _tlog_cosign.cosign(cosigned, key, name, timestamp)
        atomic_bytes(path, note)
    return {"checkpoint": cosigned.decode("utf-8"), "origin": origin, "previous_size": old_size,
            "size": size, "witness": name}  # fmt: skip


__all__ = ["consistency_from", "load_proof", "witness"]
