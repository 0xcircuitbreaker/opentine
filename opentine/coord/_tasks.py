"""Tasks and leases: ``coord/tasks/<id>`` (``tine task add|claim|heartbeat|done|list``).

A task's value is::

    {"task": ID, "title": TEXT, "status": "open"|"claimed"|"done",
     "holder": NAME|null, "fencing": N, "lease_expires_ms": MS|null,
     "updated_ms": MS}

* **claim** is one compare-and-swap ref move from the version the claimant read
  to a version naming it as holder, with ``fencing`` one higher and a lease
  ending ``ttl`` from now. It succeeds only on an ``open`` task or one whose
  lease has expired; of any number of racing claimants exactly one CAS wins.
* **heartbeat** extends the lease and **done** closes the task, each only for
  the current holder presenting the current fencing token before its lease
  ends. A stale holder -- one whose lease expired or was re-claimed, so its
  token is lower -- is refused (:class:`LeaseError`, ``code="stale"``), so it
  can never overwrite a newer claimant's work.

The fencing token only ever grows (the ref's annotation chain keeps every
version), so downstream writes can be ordered and fenced by it.
"""

from __future__ import annotations

import re
import time
from typing import Any

from opentine.coord._store import history, read, swap

KIND = "task"
PREFIX = "coord/tasks/"
TASK_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
MAX_TITLE = 4096
MAX_HOLDER = 256
#: Racing writers re-read and retry a lost CAS at most this many times.
MAX_ATTEMPTS = 64


class LeaseError(ValueError):
    """A refused task operation; ``code`` is ``exists|missing|held|done|stale|contended``."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def now_ms() -> int:
    return int(time.time() * 1000)


def ref_name(task: str) -> str:
    if not isinstance(task, str) or not TASK_ID.fullmatch(task):
        raise ValueError(f"invalid task id: {task!r} (lowercase [a-z0-9._-], at most 64)")
    return PREFIX + task


def _holder(holder: str) -> str:
    if not isinstance(holder, str) or not holder or len(holder) > MAX_HOLDER:
        raise ValueError("a holder is a non-empty name of at most 256 characters")
    return holder


def _ttl(ttl: float) -> int:
    if not 0 < ttl <= 86_400 * 7:
        raise ValueError("lease ttl must be between 0 and 7 days")
    return int(ttl * 1000)


def add(repo: Any, task: str, title: str = "", *, now: int | None = None) -> dict[str, Any]:
    if len(title) > MAX_TITLE:
        raise ValueError("task title is too long")
    value = {"task": task, "title": title, "status": "open", "holder": None, "fencing": 0,
             "lease_expires_ms": None, "updated_ms": now_ms() if now is None else now}  # fmt: skip
    name = ref_name(task)
    if read(repo, name, KIND)[0] is not None or swap(repo, name, KIND, value, None) is None:
        raise LeaseError("exists", f"task {task} already exists")
    return value


def get(repo: Any, task: str) -> dict[str, Any]:
    _, value = read(repo, ref_name(task), KIND)
    if value is None:
        raise LeaseError("missing", f"no such task: {task}")
    return value


def expired(value: dict[str, Any], now: int) -> bool:
    expires = value.get("lease_expires_ms")
    return value["status"] == "claimed" and isinstance(expires, int) and expires <= now


def claim(
    repo: Any, task: str, holder: str, ttl: float = 60.0, *, now: int | None = None
) -> dict[str, Any]:
    """Take *task*'s lease; the new value (``fencing`` is the caller's token)."""
    name, holder, span = ref_name(task), _holder(holder), _ttl(ttl)
    for _ in range(MAX_ATTEMPTS):
        oid, value = read(repo, name, KIND)
        if value is None:
            raise LeaseError("missing", f"no such task: {task}")
        moment = now_ms() if now is None else now
        if value["status"] == "done":
            raise LeaseError("done", f"task {task} is done")
        if value["status"] == "claimed" and not expired(value, moment):
            raise LeaseError("held", f"task {task} is held by {value['holder']} "
                             f"(fencing {value['fencing']})")  # fmt: skip
        new = {**value, "status": "claimed", "holder": holder,
               "fencing": int(value["fencing"]) + 1, "lease_expires_ms": moment + span,
               "updated_ms": moment}  # fmt: skip
        if swap(repo, name, KIND, new, oid) is not None:
            return new
    raise LeaseError("contended", f"task {task}: too many concurrent claims")


def _as_holder(
    repo: Any, task: str, holder: str, fencing: int, change: Any, now: int | None
) -> dict[str, Any]:
    name = ref_name(task)
    for _ in range(MAX_ATTEMPTS):
        oid, value = read(repo, name, KIND)
        if value is None:
            raise LeaseError("missing", f"no such task: {task}")
        moment = now_ms() if now is None else now
        if (
            value["status"] != "claimed"
            or value["holder"] != holder
            or value["fencing"] != fencing
            or expired(value, moment)
        ):
            raise LeaseError("stale", f"task {task}: {holder} (fencing {fencing}) no longer "
                             f"holds the lease (current fencing {value['fencing']})")  # fmt: skip
        delta = change(moment) if callable(change) else change
        new = {**value, **delta, "updated_ms": moment}
        if swap(repo, name, KIND, new, oid) is not None:
            return new
    raise LeaseError("contended", f"task {task}: too many concurrent writers")


def heartbeat(
    repo: Any, task: str, holder: str, fencing: int, ttl: float = 60.0, *, now: int | None = None
) -> dict[str, Any]:
    span = _ttl(ttl)
    return _as_holder(repo, task, holder, fencing,
                      lambda moment: {"lease_expires_ms": moment + span}, now)  # fmt: skip


def done(
    repo: Any, task: str, holder: str, fencing: int, *, now: int | None = None
) -> dict[str, Any]:
    return _as_holder(repo, task, holder, fencing,
                      {"status": "done", "lease_expires_ms": None}, now)  # fmt: skip


def list_tasks(repo: Any) -> list[dict[str, Any]]:
    rows = []
    for name in sorted(repo.list_refs()):
        if name.startswith(PREFIX):
            value = read(repo, name, KIND)[1]
            if value is not None:
                rows.append(value)
    return rows


def task_history(repo: Any, task: str) -> list[dict[str, Any]]:
    return history(repo, repo.read_ref(ref_name(task)))


__all__ = ["KIND", "LeaseError", "add", "claim", "done", "expired", "get", "heartbeat",
           "list_tasks", "ref_name", "task_history"]  # fmt: skip
