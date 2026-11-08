"""The op log: one ``opentine-log/1`` entry per ref-moving ``tine`` command (0.36).

Every local ref write (``commit_ref``, ``update_refs`` and its roll-forward,
``delete_ref``) reports what it moved through :func:`note_move`. Inside
:func:`operation` (``tine`` wraps every verb in one) the moves are gathered and,
when the verb ends, written as one entry per repository: op id, command, actor,
time, the leaf hash of the previous entry (a hash chain alongside the Merkle
tree), and each ref's first ``old`` and last ``new``. Writers outside an
operation -- library callers, opentine before 0.36 -- do not log; ``tine undo``
finds the gaps they leave (:mod:`opentine._undo`). The log is history, not
authority: undo re-checks every ref it moves by compare-and-swap.
"""

from __future__ import annotations

import contextlib
import contextvars
import getpass
import hashlib
import json
import secrets
import sys
import time
from collections.abc import Iterator
from pathlib import Path

from opentine._cli_text import plain_text
from opentine.kernel import canonical_json
from opentine.repository import _tlog, _tlog_note
from opentine.repository._paths import internal_path

OP_FORMAT = "opentine-op/1"
ORIGIN = "opentine.local/log/op"

_current: contextvars.ContextVar[_Op | None] = contextvars.ContextVar("tine_op", default=None)


class _Op:
    def __init__(self, command: str, undoes: str | None) -> None:
        self.command, self.undoes = command, undoes
        self.moves: dict[Path, dict[str, list]] = {}  # base -> ref -> [old, new]
        self.actors: list[str] = []
        self.note: str | None = None  # 0.45: e.g. a push's --allow-unredacted reason


def log_root(base: Path) -> Path:
    return internal_path(Path(base), "log", "op")


def _actor() -> str:
    try:
        return getpass.getuser()
    except Exception:  # noqa: BLE001 - no login name (containers, services)
        return "local"


def reflog_digest(row: dict) -> str:
    """Identity of one reflog row: undo checks the ref's newest row is still the op's."""
    return hashlib.sha256(canonical_json(row)).hexdigest()


def note_move(base: Path, ref: str, row: dict) -> None:
    """Report one ref write (its reflog row); it is logged only inside an :func:`operation`."""
    op = _current.get()
    if op is None:
        return
    refs = op.moves.setdefault(Path(base), {})
    move = refs.setdefault(ref, [row["old"], None, None])
    move[1:] = [row["new"], reflog_digest(row)]
    actor = row["actor"]
    if actor not in op.actors:
        op.actors.append(actor)


def note(text: str, *, base: Path | None = None) -> None:
    """Attach *text* to the running op's log entry (0.45).

    With *base*, the note is also logged at once as an entry of its own (no ref
    moves), and a failed write raises: a verb such as ``push`` moves no local
    ref, so its end-of-op entry would never be written and the note would be lost.
    """
    op = _current.get()
    if op is not None:
        op.note = text if op.note is None else f"{op.note}; {text}"
    if base is not None:
        entry = _Op(op.command if op is not None else "tine", None)
        entry.note = text
        record(Path(base), entry, [])


def set_undoes(op_id: str) -> None:
    if (op := _current.get()) is not None:
        op.undoes = op_id


@contextlib.contextmanager
def operation(command: str | None) -> Iterator[None]:
    """Gather this verb's ref moves; log them (even when it fails part-way) at exit."""
    op = _Op(command or "tine", None)
    token = _current.set(op)
    try:
        yield
    finally:
        _current.reset(token)
        for base, refs in op.moves.items():
            rows = [
                {"new": n, "old": o, "ref": r, "reflog": d}
                for r, (o, n, d) in sorted(refs.items())
                if o != n
            ]
            try:
                if rows:
                    record(base, op, rows)
            except (OSError, ValueError) as exc:  # the refs moved: undo will see a gap
                print(f"tine: warning: op log not written: {plain_text(exc)}", file=sys.stderr)


def record(base: Path, op: _Op, rows: list[dict]) -> None:
    body = {
        "actor": _actor(),
        "command": op.command,
        "format": OP_FORMAT,
        "id": secrets.token_hex(8),
        "refs": rows,
        "time_ns": str(time.time_ns()),
        "undoes": op.undoes,
        "writers": op.actors,
    }
    if op.note is not None:  # absent otherwise, so pre-0.45 entries are unchanged
        body["note"] = op.note

    def chained(entries: list[bytes]) -> bytes:
        prev = _tlog.leaf_hash(entries[-1]).hex() if entries else None
        return canonical_json({**body, "prev": prev})

    _tlog_note.append(log_root(base), ORIGIN, chained)


def read_ops(base: Path, vkey: str | None = None) -> list[dict]:
    """Every op, oldest first, from a verified log whose hash chain is unbroken."""
    entries = _tlog_note.verify_log(log_root(base), ORIGIN, vkey)
    ops, prev = [], None
    for index, entry in enumerate(entries):
        try:
            op = json.loads(entry)
        except ValueError as exc:
            raise _tlog.LogError(f"op {index} is not JSON") from exc
        if not isinstance(op, dict) or op.get("format") != OP_FORMAT:
            raise _tlog.LogError(f"op {index} is not an {OP_FORMAT} record")
        if op.get("prev") != prev:
            raise _tlog.LogError(f"op {index} breaks the hash chain")
        prev = _tlog.leaf_hash(entry).hex()
        ops.append({**op, "index": index})
    return ops
