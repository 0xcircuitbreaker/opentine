"""Stable machine-readable JSON for the v3 repository read verbs.

Every function here builds a plain dict and hands it to the one writer,
``opentine._cli_json.emit``. That is deliberate: ``emit`` applies ``json_safe``,
sorts keys, and is the reason each object carries a ``command`` naming its
schema. Re-implementing any of that here would let the v3 surface drift away
from the .tine surface one field at a time. The same rules therefore hold:
within a major version fields are added, never renamed or removed; a failure
that stops the command producing a result is a human message on stderr and a
non-zero exit, never a JSON object.

``tine repo-show REF --json``
    ``command``        ``"repo-show"``
    ``repo``           str — repository the run was read from
    ``ref``            str — the ref or run oid as the caller spelled it
    ``run_object_id``  str — the v3 ``run:sha256:…`` oid ``ref`` resolved to
    ``run``            object — as ``tine show --json`` but without
                       ``short_id``, which is meaningless on a v3 oid: ``id``,
                       ``status``, ``model``, ``created_at``, ``total_cost``,
                       ``step_count``, ``tags``, ``user_prompt``,
                       ``system_prompt``
    ``steps``          array — the ``tine show --json`` step shape, again minus
                       ``short_id``; ``id`` is the event's v3 oid

``tine context EVENT --json``
    ``command``  ``"context"``
    ``repo``     str
    ``event``    str — the event oid the slice was requested for
    ``depth``    int — the causal depth requested (default 8, as MCP)
    ``count``    int — number of entries
    ``entries``  array — oldest first: ``oid``, ``object_type``, ``kind``

``tine repo-log REF --json``
    ``command``  ``"repo-log"``
    ``repo``     str
    ``ref``      str
    ``count``    int
    ``entries``  array — ``oid``, ``object_type``, ``kind``

``entries`` carries no payload in either verb, exactly like the human line:
event payloads are unbounded recorded content, and ``tine object OID`` is the
verb that resolves one. The full contract table lives in docs/REPOSITORY.md.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from opentine._cli_json import _step, emit
from opentine._repo_cli_render import entry_kind


def _entries(entries: list[Any]) -> list[dict[str, Any]]:
    return [
        {"oid": entry.oid, "object_type": entry.object_type, "kind": entry_kind(entry)}
        for entry in entries
    ]


def emit_repo_log(repo: str | Path, ref: str, entries: list[Any]) -> None:
    emit(
        {
            "command": "repo-log",
            "repo": str(repo),
            "ref": ref,
            "count": len(entries),
            "entries": _entries(entries),
        }
    )


def emit_context(repo: str | Path, event_id: str, depth: int, entries: list[Any]) -> None:
    emit(
        {
            "command": "context",
            "repo": str(repo),
            "event": event_id,
            "depth": depth,
            "count": len(entries),
            "entries": _entries(entries),
        }
    )


def _v3_step(step: Any) -> dict[str, Any]:
    """The .tine step object with ``short_id`` dropped.

    ``short_id`` is a twelve-character prefix, which on the ``run:sha256:…`` ids
    a v3 event carries is the constant ``"event:sha25"`` — a field that is the
    same for every step is worse than absent, so the v3 schema omits it.
    """
    payload = _step(step)
    payload.pop("short_id", None)
    return payload


def emit_repo_show(repo: str | Path, ref: str, run: Any, run_object_id: str) -> None:
    emit(
        {
            "command": "repo-show",
            "repo": str(repo),
            "ref": ref,
            "run_object_id": run_object_id,
            "run": {
                "id": run.id,
                "status": run.status.value,
                "model": run.model_info,
                "created_at": run.created_at,
                "total_cost": run.total_cost,
                "step_count": len(run.steps),
                "tags": list(run.tags),
                "user_prompt": run.user_prompt,
                "system_prompt": run.system_prompt,
            },
            "steps": [_v3_step(step) for step in run.steps],
        }
    )
