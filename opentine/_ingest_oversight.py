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

Advisory findings (``ingest.duplicate-input``) open nothing (D12). Nothing is
stored: there is no index to plant or delete items in. An item reaches a tier
only through a ``[[route]] source = "ingest"`` row of the pinned policy.
"""

from __future__ import annotations

from typing import Any

SOURCE = "ingest"


def stream_items(repo: Any, stream: str) -> set[str]:
    from opentine._ingest_policy import anchor_id
    from opentine._ingest_verify import verify

    anchor = anchor_id(stream)
    try:
        report = verify(repo, stream)
    except Exception:  # noqa: BLE001 - a stream that cannot be checked is a finding
        return {anchor}
    return {f["batch"] or anchor for f in report["findings"] if f["level"] == "fail"}


def items(repo: Any) -> list[dict[str, Any]]:
    """``[{"item", "source"}]`` for every failing finding of every held stream."""
    from opentine._ingest_holds import streams

    found: set[str] = set()
    for stream in streams(repo):
        found |= stream_items(repo, stream)
    return [{"item": f"{SOURCE}:{oid}", "source": SOURCE} for oid in sorted(found)]


__all__ = ["SOURCE", "items", "stream_items"]
