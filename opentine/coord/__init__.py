"""``opentine-coord/1``: tasks, leases and mailboxes kept as refs under ``coord/``.

Every coordination record is an **annotation** (SPEC 1.5.5) named by a
``coord/*`` ref. Each change writes a new annotation whose ``previous_id`` is
the one before, and moves the ref by compare-and-swap, so the ref's history is
the record's audit trail and a lost race is a refused CAS, never a lost update.

* :mod:`opentine.coord._tasks` -- ``coord/tasks/<id>``: a task, its lease and
  its fencing token (``tine task``).
* :mod:`opentine.coord._mailbox` -- ``coord/mailbox/<fleet>/<member>``: steer
  messages for one fleet member (``tine fleet send``), delivered by the
  ``opentine-hook/1`` turn callback in :mod:`opentine._hook_mailbox`.
"""

FORMAT = "opentine-coord/1"

__all__ = ["FORMAT"]
