"""The merge queue: ``coord/merge-queue/<id>`` (0.47, F2, SPEC 4.19).

A queue owns one target ref (``heads/main``) and holds the runs waiting to
merge into it. Its value is::

    {"queue": ID, "target": REF, "gates": <opentine-merge-gates/1> | null,
     "head": RUN | null, "entries": [{"run", "by", "enqueued_ms"}],
     "holder": NAME | null, "fencing": N, "lease_expires_ms": MS | null,
     "landed": [{"run", "merge", "fencing", "attestation"}],
     "rejected": [{"run", "reason", "fencing"}], "updated_ms": MS}

A worker **claims** the queue (a lease with a fencing token one higher, as
:mod:`opentine.coord._tasks`), then **lands** the first entry: gates checked,
the entry merged onto ``head`` (or fast-forwarded onto an empty target), a
signed ``opentine.merge`` attestation written, and then *one* compare-and-swap
of the queue record that pops the entry, moves ``head``, appends to ``landed``
and releases the lease. That CAS is the commit point, so an entry lands at
most once: a holder whose lease expired or whose token is not current is
refused (``stale``), and one killed before the CAS leaves only unreferenced
objects (merges are deterministic, so the next holder writes the very same
ones). The target ref then follows ``head`` (:func:`sync_target`); the queue
owns it, and every claim and land re-syncs it first.
"""

from __future__ import annotations

from typing import Any

from opentine.coord._store import history, read, swap
from opentine.coord._tasks import MAX_ATTEMPTS, TASK_ID, LeaseError, _holder, _ttl, now_ms

KIND = "merge-queue"
PREFIX = "coord/merge-queue/"
MAX_ENTRIES = 4096
MAX_LANDED = 1024


def ref_name(queue: str) -> str:
    if not isinstance(queue, str) or not TASK_ID.fullmatch(queue):
        raise ValueError(f"invalid queue id: {queue!r} (lowercase [a-z0-9._-], at most 64)")
    return PREFIX + queue


def get(repo: Any, queue: str) -> dict[str, Any]:
    value = read(repo, ref_name(queue), KIND)[1]
    if value is None:
        raise LeaseError("missing", f"no such merge queue: {queue}")
    return value


def _update(repo: Any, queue: str, change: Any) -> dict[str, Any]:
    """Apply *change(value, now) -> new value* by CAS, retrying a lost race."""
    name = ref_name(queue)
    for _ in range(MAX_ATTEMPTS):
        oid, value = read(repo, name, KIND)
        if value is None:
            raise LeaseError("missing", f"no such merge queue: {queue}")
        moment = now_ms()
        new = {**change(value, moment), "updated_ms": moment}
        if swap(repo, name, KIND, new, oid) is not None:
            return new
    raise LeaseError("contended", f"merge queue {queue}: too many concurrent writers")


def init(repo: Any, queue: str, target: str, gates: dict[str, Any] | None = None) -> dict:
    from opentine._merge_gates import check_policy

    if gates is not None:
        check_policy(gates)
    value = {"queue": queue, "target": target, "gates": gates, "head": repo.read_ref(target),
             "entries": [], "holder": None, "fencing": 0, "lease_expires_ms": None,
             "landed": [], "rejected": [], "updated_ms": now_ms()}  # fmt: skip
    name = ref_name(queue)
    if read(repo, name, KIND)[0] is not None or swap(repo, name, KIND, value, None) is None:
        raise LeaseError("exists", f"merge queue {queue} already exists")
    return value


def enqueue(repo: Any, queue: str, run: str, by: str) -> dict[str, Any]:
    by = _holder(by)

    def change(value: dict[str, Any], moment: int) -> dict[str, Any]:
        seen = {e["run"] for e in value["entries"]} | {e["run"] for e in value["landed"]}
        if run in seen:
            raise LeaseError("exists", f"{run} is already queued or landed")
        if len(value["entries"]) >= MAX_ENTRIES:
            raise LeaseError("full", f"merge queue {queue} is full")
        entry = {"run": run, "by": by, "enqueued_ms": moment}
        return {**value, "entries": [*value["entries"], entry]}

    if not repo.has(run) or repo.get(run).object_type != "run":
        raise LeaseError("missing", f"no such run: {run}")
    return _update(repo, queue, change)


def _expired(value: dict[str, Any], moment: int) -> bool:
    expires = value.get("lease_expires_ms")
    return value["holder"] is not None and isinstance(expires, int) and expires <= moment


def claim(repo: Any, queue: str, holder: str, ttl: float = 60.0) -> dict[str, Any]:
    """Take the queue's lease; the new value (``fencing`` is the caller's token)."""
    holder, span = _holder(holder), _ttl(ttl)
    sync_target(repo, queue)

    def change(value: dict[str, Any], moment: int) -> dict[str, Any]:
        if value["holder"] is not None and not _expired(value, moment):
            raise LeaseError("held", f"merge queue {queue} is held by {value['holder']} "
                             f"(fencing {value['fencing']})")  # fmt: skip
        if not value["entries"]:
            raise LeaseError("empty", f"merge queue {queue} is empty")
        return {**value, "holder": holder, "fencing": value["fencing"] + 1,
                "lease_expires_ms": moment + span}  # fmt: skip

    return _update(repo, queue, change)


def _holds(value: dict[str, Any], holder: str, fencing: int, moment: int, queue: str) -> None:
    if value["holder"] != holder or value["fencing"] != fencing or _expired(value, moment):
        raise LeaseError("stale", f"merge queue {queue}: {holder} (fencing {fencing}) no longer "
                         f"holds the lease (current fencing {value['fencing']})")  # fmt: skip


def heartbeat(repo: Any, queue: str, holder: str, fencing: int, ttl: float = 60.0) -> dict:
    span = _ttl(ttl)

    def change(value: dict[str, Any], moment: int) -> dict[str, Any]:
        _holds(value, holder, fencing, moment, queue)
        return {**value, "lease_expires_ms": moment + span}

    return _update(repo, queue, change)


def land(
    repo: Any, queue: str, holder: str, fencing: int, *, evidence: Any = None,
    key: Any = None, algorithm: str = "ed25519", merged_at: str | None = None,
) -> dict[str, Any]:  # fmt: skip
    """Land the first entry; ``{"status": "landed"|"rejected", "run", "merge", ...}``."""
    from opentine.coord._merge_land import prepare

    sync_target(repo, queue)
    name = ref_name(queue)
    for _ in range(MAX_ATTEMPTS):
        oid, value = read(repo, name, KIND)
        if value is None:
            raise LeaseError("missing", f"no such merge queue: {queue}")
        _holds(value, holder, fencing, now_ms(), queue)
        if value["head"] is not None and repo.read_ref(value["target"]) != value["head"]:
            raise LeaseError("diverged", f"merge queue {queue}: {value['target']} moved outside "
                             "the queue; it is not overwritten")  # fmt: skip
        if not value["entries"]:
            raise LeaseError("empty", f"merge queue {queue} is empty")
        outcome = prepare(repo, value, evidence, key=key, algorithm=algorithm, actor=holder,
                          merged_at=merged_at)  # fmt: skip
        new = {**value, "entries": value["entries"][1:], "holder": None,
               "lease_expires_ms": None, "updated_ms": now_ms()}  # fmt: skip
        if outcome["status"] == "landed":
            row = {k: outcome[k] for k in ("run", "merge", "fencing", "attestation")}
            new.update(head=outcome["merge"], landed=[*value["landed"], row][-MAX_LANDED:])
        else:
            row = {"run": outcome["run"], "reason": outcome["reason"], "fencing": fencing}
            new["rejected"] = [*value["rejected"], row][-MAX_LANDED:]
        links = [x for x in (outcome["merge"], outcome["attestation"]) if x]
        if swap(repo, name, KIND, new, oid, links) is not None:
            sync_target(repo, queue)
            return outcome
    raise LeaseError("contended", f"merge queue {queue}: too many concurrent writers")


def sync_target(repo: Any, queue: str) -> str | None:
    """Move the target ref to the queue's ``head`` when it lags; the head."""
    from opentine.repository._ref_retry import RefCasMismatch

    target = get(repo, queue)["target"]
    current = repo.read_ref(target)  # before the value: a head read later is never older
    value = get(repo, queue)
    if value["head"] and current != value["head"]:
        from opentine.coord._merge_land import _contains

        if current is not None and (
            not repo.has(current) or not _contains(repo, value["head"], current)
        ):
            return value["head"]  # moved outside the queue: never clobber it (land refuses)
        try:
            repo.update_ref(value["target"], value["head"], expected_old=current, actor="merge")
        except RefCasMismatch:
            pass  # another syncer moved it; it moves only to a queue head
    return value["head"]


def queue_history(repo: Any, queue: str) -> list[dict[str, Any]]:
    return history(repo, repo.read_ref(ref_name(queue)))


__all__ = ["KIND", "claim", "enqueue", "get", "heartbeat", "init", "land", "queue_history",
           "ref_name", "sync_target"]  # fmt: skip
