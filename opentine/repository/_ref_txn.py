"""Atomic multi-ref updates with a crash journal (``Repo.update_refs``).

Protocol, per transaction ``T``:

1. take ``txn/T.lock`` (pid/host/time stamped, :mod:`._lockfile`), then every
   ref's guard lock in sorted order (no lock-order deadlock between writers);
2. compare-and-swap every ref against its expected old value;
3. write ``txn/T.json`` durably -- **the commit point**;
4. replace each ref and append its reflog row;
5. delete the journal, then the locks.

A crash before 3 changed nothing (the next writer breaks the dead locks); after
3, the next ref write rolls the journal *forward* first, by compare-and-swap: a
ref at its new value is skipped, one at its old value is moved, anything else
(changed by a writer that broke a dead lock in the gap) is left alone. A journal
that does not parse, names an illegal ref or an absent object is never applied:
it is renamed ``T.rejected`` (kept for inspection, no longer blocking writers).
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import secrets
from pathlib import Path

from opentine._canon import _fsync_dir
from opentine.kernel import KernelError, canonical_json, parse_oid
from opentine.repository._lockfile import acquire, provably_dead
from opentine.repository._paths import durable_directory, internal_path
from opentine.repository._ref_store import read_ref_oid
from opentine.repository._reflog import append_reflog, reflog_entry
from opentine.repository._refs import normalize_ref, validate_ref_oid, validate_ref_target

TXN_FORMAT = "opentine-ref-txn/1"
MAX_TXN_REFS = 4096
MAX_JOURNAL_BYTES = 4 * 1024 * 1024
_TXN_ID = re.compile(r"^[0-9a-f]{32}$")


def _ref_path(base: Path, name: str) -> Path:
    return internal_path(base, "refs", *Path(name).parts)


def _lock(path: Path) -> Path:
    durable_directory(path.parent)
    try:
        with os.fdopen(acquire(path), "wb"):
            pass  # stamped by acquire; the file only has to exist
    except FileExistsError as exc:
        raise ValueError(f"ref is locked by a concurrent writer ({path})") from exc
    return path


def _write_ref(base: Path, name: str, new_oid: str) -> None:
    path = _ref_path(base, name)
    staging = path.with_name(path.name + "..lock")  # see commit_ref for the name
    fd = os.open(staging, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write((new_oid + "\n").encode("ascii"))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(staging, path)
    finally:
        staging.unlink(missing_ok=True)
    _fsync_dir(path.parent)


def _apply(base: Path, record: dict, actor: str) -> None:
    for row in record["updates"]:
        current = read_ref_oid(base, row["ref"])
        if current == row["new"] or current != row["old"]:
            continue  # already applied, or moved since by someone else: never clobber
        entry = reflog_entry(row["ref"], current, row["new"], actor)
        _write_ref(base, row["ref"], row["new"])
        append_reflog(base, row["ref"], entry)


def parse_journal(base: Path, raw: bytes, txn_id: str) -> dict:
    """A journal's record, or ``ValueError``: every field is checked before use."""
    from opentine.repository.store import Repo

    if len(raw) > MAX_JOURNAL_BYTES:
        raise ValueError("journal exceeds its size limit")
    record = json.loads(raw)
    if not isinstance(record, dict) or set(record) != {"actor", "format", "id", "updates"}:
        raise ValueError("journal has the wrong fields")
    if record["format"] != TXN_FORMAT or record["id"] != txn_id:
        raise ValueError("journal format or id mismatch")
    if not isinstance(record["actor"], str) or len(record["actor"]) > 4096:
        raise ValueError("journal actor is malformed")
    rows = record["updates"]
    if not isinstance(rows, list) or not 1 <= len(rows) <= MAX_TXN_REFS:
        raise ValueError("journal updates are malformed")
    seen: set[str] = set()
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"new", "old", "ref"}:
            raise ValueError("journal row has the wrong fields")
        if not isinstance(row["ref"], str) or normalize_ref(row["ref"]) != row["ref"]:
            raise ValueError("journal names an illegal ref")
        if row["ref"] in seen:
            raise ValueError("journal names a ref twice")
        seen.add(row["ref"])
        if not isinstance(row["new"], str) or not isinstance(row["old"], (str, type(None))):
            raise ValueError("journal values are malformed")
        if row["old"] is not None:
            parse_oid(row["old"])
        validate_ref_oid(row["ref"], row["new"])
        try:  # the same target rules update_refs checked before writing it
            target = Repo(base).get(row["new"])
        except (KeyError, KernelError, OSError) as exc:
            raise ValueError("journal names an object the repository cannot read") from exc
        validate_ref_target(row["ref"], target.object_type, target.payload())
    return record


def _journals(base: Path) -> list[Path]:
    directory = internal_path(base, "txn")
    try:
        names = sorted(os.listdir(directory))
    except FileNotFoundError:
        return []
    return [directory / name for name in names if name.endswith(".json")]


def _abandoned(journal: Path) -> bool:
    lock = journal.with_suffix(".lock")
    return not lock.exists() or provably_dead(lock)


def pending(base: Path) -> list[str]:
    """Ids of journals left by a dead writer (what the next write rolls forward)."""
    return [path.stem for path in _journals(base) if _abandoned(path)]


def recover(base: Path) -> list[str]:
    """Roll every abandoned journal forward (or reject it); return the ids handled."""
    handled: list[str] = []
    for journal in _journals(base):
        txn_id = journal.stem
        if not _abandoned(journal):
            continue  # a live transaction: its owner finishes it
        held: list[Path] = []
        try:
            held.append(_lock(journal.with_suffix(".lock")))
        except ValueError:
            continue  # another recoverer took it first
        try:
            if not journal.exists():
                continue  # finished by its owner, or recovered, since listing
            try:
                if not _TXN_ID.fullmatch(txn_id):
                    raise ValueError("journal name is not a transaction id")
                with open(journal, "rb") as handle:
                    raw = handle.read(MAX_JOURNAL_BYTES + 1)
                record = parse_journal(base, raw, txn_id)
            except (OSError, ValueError, UnicodeDecodeError):
                # Kept for inspection, never applied, and no longer blocking.
                with contextlib.suppress(FileNotFoundError):  # gone meanwhile
                    os.replace(journal, journal.with_name(f"{txn_id}.rejected"))
                handled.append(txn_id)
                continue
            for name in sorted(row["ref"] for row in record["updates"]):
                held.append(_lock(_ref_lock(base, name)))
            _apply(base, record, f"txn-recover:{record['actor']}"[:4096])
            journal.unlink(missing_ok=True)
            _fsync_dir(journal.parent)
            handled.append(txn_id)
        except ValueError:
            continue  # a ref is held by a live writer; the next write retries
        finally:
            for path in reversed(held):
                path.unlink(missing_ok=True)
    return handled


def _ref_lock(base: Path, name: str) -> Path:
    path = _ref_path(base, name)
    return path.with_name(path.name + ".lock")


def update_refs(base: Path, updates: list[tuple[str, str, str | None]], actor: str) -> None:
    """Move every ref or none; each ``(ref, new, expected_old)`` is compare-and-swap."""
    names = [name for name, _, _ in updates]
    if not names or len(names) > MAX_TXN_REFS or len(set(names)) != len(names):
        raise ValueError("update_refs needs 1..4096 distinct refs")
    reflog_entry(names[0], None, updates[0][1], actor)  # validates the actor first
    directory = internal_path(base, "txn")
    durable_directory(directory)
    txn_id = secrets.token_hex(16)
    journal = directory / f"{txn_id}.json"
    locks = [directory / f"{txn_id}.lock", *(_ref_lock(base, name) for name in sorted(names))]
    held = locked_after_recovery(base, locks)
    try:
        rows = []
        for name, new_oid, expected in sorted(updates, key=lambda row: row[0]):
            old = read_ref_oid(base, name)
            if old != expected:
                raise ValueError(
                    f"concurrent ref update on {name!r}: expected {expected!r}, found {old!r}"
                )
            rows.append({"new": new_oid, "old": old, "ref": name})
        record = {"actor": actor, "format": TXN_FORMAT, "id": txn_id, "updates": rows}
        fd = os.open(journal, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(canonical_json(record))
                handle.flush()
                os.fsync(handle.fileno())
            _fsync_dir(directory)
        except BaseException:
            journal.unlink(missing_ok=True)  # never committed: nothing to roll forward
            raise
        _apply(base, record, actor)
        journal.unlink()
        _fsync_dir(directory)
    finally:
        # A failure after the commit point keeps the journal: with these locks
        # gone it is abandoned, so the next writer rolls it forward.
        _release(held)


def _release(held: list[Path]) -> None:
    for path in reversed(held):
        path.unlink(missing_ok=True)


def locked_after_recovery(base: Path, locks: list[Path]) -> list[Path]:
    """Take *locks* with no abandoned journal pending, recovering first.

    Recovery runs before the locks, and is re-checked after: a writer that broke a
    crashed transaction's dead ref lock before its journal was rolled forward
    would otherwise commit over a half-applied transaction.
    """
    for _ in range(3):
        recover(base)
        held: list[Path] = []
        try:
            for path in locks:
                held.append(_lock(path))
        except BaseException:
            _release(held)
            raise
        if not pending(base):
            return held
        _release(held)
    raise ValueError("an interrupted ref transaction could not be recovered; retry")
