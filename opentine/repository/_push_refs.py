"""The ref moves that end a push: the head, then the run's annotation ref.

A server whose ``/v1/capabilities`` says ``"ref_txn": true`` (0.43) gets both in
one ``POST ref-txn``, applied all or none, so a push can no longer leave the
head moved and the annotation ref behind. Any other server -- every 0.34 to
0.42 one -- gets the two ``PUT /refs/<name>`` calls it always did.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import quote


def move_refs(
    client: Any,
    request_json: Any,
    prefix: str,
    caps: dict[str, Any],
    moves: list[tuple[str, str, str | None]],
    *,
    timeout: float,
    force: bool = False,
) -> None:
    """Apply ``(name, new, expected_old)`` moves in order; raises on a conflict."""
    if caps.get("ref_txn") is True:
        updates = [{"name": name, "new": new, "expected_old": old} for name, new, old in moves]
        status, _ = request_json(
            client,
            "POST",
            prefix + "/ref-txn",
            allowed=(200, 409),
            max_seconds=timeout,
            json={"updates": updates, **({"force": True} if force else {})},
        )
        if status == 409:
            raise ValueError("remote ref changed concurrently")
        return
    for position, (name, new, old) in enumerate(moves):
        body = {"expected_old": old, "new": new}
        if force and position == 0:
            body["force"] = True
        status, _ = request_json(
            client,
            "PUT",
            prefix + "/refs/" + quote(name, safe=""),
            allowed=(200, 409),
            max_seconds=timeout,
            json=body,
        )
        if status == 409:
            noun = "ref" if position == 0 else "annotation ref"
            raise ValueError(f"remote {noun} changed concurrently")


__all__ = ["move_refs"]
