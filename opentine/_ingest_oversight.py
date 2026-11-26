"""Ingest gaps and sampling-policy violations in the oversight queue (0.77).

:func:`items` feeds the ``ingest`` source of the oversight queue
(:mod:`opentine._oversight_queue`). Every stream the repository holds a policy
or head for is checked with ``tine ingest verify``
(:mod:`opentine._ingest_verify`) each time the queue is built, and every
``fail`` finding opens one item:

* ``ingest:<annotation>`` -- the batch (a gap, reorder, replay, bad count,
  hidden drop, policy switch, wrong signer) the finding names;
* ``ingest:<blob>`` -- the stream's anchor, for a finding that names no batch
  (no held policy, more than one held head, an unreadable chain).

From 0.84 the stream's sealed segments and their sampling audits are checked
the same way with ``tine ingest segments`` (:mod:`opentine._rl_verify`), and
every ``fail`` finding there (a failed audit, a forged or broken segment)
opens ``ingest:<segment>`` for the segment the finding names.

Advisory findings (``ingest.duplicate-input``, ``ingest.segment-unaudited``,
``ingest.segment-pending``) open nothing (D12). Nothing is
stored: there is no index to plant or delete items in. An item reaches a tier
only through a ``[[route]] source = "ingest"`` row of the pinned policy.
"""

from __future__ import annotations

from typing import Any

SOURCE = "ingest"


def stream_items(repo: Any, stream: str) -> set[str]:
    from opentine._ingest_policy import anchor_id
    from opentine._ingest_verify import verify
    from opentine._rl_segment import chain
    from opentine._rl_verify import verify as segments

    anchor = anchor_id(stream)
    try:
        report = verify(repo, stream)
        ids, broken = chain(repo, stream)
        sealed = segments(repo, stream) if ids or broken else {"findings": []}
    except Exception:  # noqa: BLE001 - a stream that cannot be checked is a finding
        return {anchor}
    found = {f["batch"] or anchor for f in report["findings"] if f["level"] == "fail"}
    return found | {f["record"] or anchor for f in sealed["findings"] if f["level"] == "fail"}


def items(repo: Any) -> list[dict[str, Any]]:
    """``[{"item", "source"}]`` for every failing finding of every held stream."""
    from opentine._ingest_holds import streams

    found: set[str] = set()
    for stream in streams(repo):
        found |= stream_items(repo, stream)
    return [{"item": f"{SOURCE}:{oid}", "source": SOURCE} for oid in sorted(found)]


__all__ = ["SOURCE", "items", "stream_items"]
