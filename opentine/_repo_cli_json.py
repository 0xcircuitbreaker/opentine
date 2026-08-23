"""Stable machine-readable JSON for the v3 repository verbs.

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

``tine repo-diff LEFT RIGHT --json``
    ``command``         ``"repo-diff"``
    ``repo``            str
    ``left``/``right``  str — the ref or oid as the caller spelled it
    ``left_id``         str — the ``run:sha256:…`` oid ``left`` resolved to
    ``right_id``        str — likewise for ``right``
    ``identical``       bool — the ``--exit-code`` predicate, so a consumer of
                        the object and a caller reading ``$?`` cannot disagree
    plus every field of ``SemanticDiff`` verbatim: ``common_events``,
    ``only_left``, ``only_right``, ``changed``, ``summary``. The envelope keys
    are written last, so a future engine field can never shadow one of them.

``tine repo-search [QUERY] --json``
    ``command``           ``"repo-search"`` — a distinct schema from the legacy
                          index-backed ``"search"``, which emits ``runs``
    ``repo``              str
    ``query``             str — empty when the caller passed none
    ``successful_only``   bool — false only with ``--include-unsuccessful``
    ``limit``/``min_score``/``model``  the filters as requested; the two
                          optional ones are null when unset
    ``count``             int — rows in ``results`` (never more than ``limit``)
    ``results``           array — ``SearchResult`` verbatim: ``run_id``,
                          ``status``, ``score`` (null when unevaluated),
                          ``cost``, ``latency``, ``models``, ``matched_text``

``entries`` carries no payload in either verb, exactly like the human line:
event payloads are unbounded recorded content, and ``tine object OID`` is the
verb that resolves one. The full contract table lives in docs/REPOSITORY.md.

Mutating verbs: --json is a receipt, never a plan
-------------------------------------------------
``attest``, ``evaluate``, and ``promote`` write. Their ``--json`` object is
emitted **only after the write has succeeded**, so receiving one is proof the
object or ref landed; a failure that stops the result — a CAS conflict, an
unresolvable or non-run target, a claim that is not a JSON object — stays a
single ``tine <verb>: <message>`` line on stderr with exit 1 through the
``cmd_repo`` envelope, and prints no JSON at all. A consumer therefore never has
to parse an object to learn whether the repository changed: stdout is empty on
failure. Their builders live next to the verbs in ``_repo_cli_write.py``, but
they go through the same ``emit`` and follow every rule above.

``tine attest TARGET --json``
    ``command`` ``"attest"``; ``repo``; ``target`` str — as the caller spelled
    it; ``run_id`` str — the ``run:sha256:…`` oid it resolved to;
    ``attestation_id`` str — the new ``attestation:sha256:…`` oid; ``signer``
    str; ``claim`` object — verbatim as stored; ``evidence_ids`` array;
    ``signed`` bool — always ``false``, because v3 has no attestation signing
    helper yet, so the ``signer`` label is self-asserted.

``tine evaluate TARGET --json``
    ``command`` ``"evaluate"``; ``repo``; ``target``; ``run_id``;
    ``attestation_id``; ``evaluator`` str — stored as the attestation's
    ``signer``; ``scores`` object of finite floats; ``signed`` bool — always
    ``false``. The object written is an ``attest`` with the claim fixed to
    ``{"kind": "evaluation", "scores": …}``, the one shape ``repo-search`` and
    ``repo-diff``'s ``summary.evaluations`` read back.

``tine promote TARGET --json``
    ``command`` ``"promote"``; ``repo``; ``target``; ``run_id``; ``name`` str;
    ``ref`` str — always ``"promotions/<name>"``; ``expected_old`` str or null —
    the compare-and-swap value as given; ``created`` bool — true exactly when
    ``expected_old`` was null, which is the *expect-absent* case, so a promotion
    that already exists can only be moved by naming its current oid.
"""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from typing import Any

from opentine._cli_json import emit
from opentine._cli_json_rows import _step
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


def emit_repo_diff(
    repo: str | Path,
    left: str,
    right: str,
    left_id: str,
    right_id: str,
    diff: Any,
    identical: bool,
) -> None:
    """Emit the engine's ``SemanticDiff`` plus only the facts the CLI added.

    ``asdict(diff)`` is splatted first and the envelope keys written after it, so
    the diff is exposed field-for-field — a new engine field appears here for free
    — while ``command`` and the resolved ids stay the CLI's to define.
    """
    emit(
        {
            **asdict(diff),
            "command": "repo-diff",
            "repo": str(repo),
            "left": left,
            "right": right,
            "left_id": left_id,
            "right_id": right_id,
            "identical": identical,
        }
    )


def emit_repo_search(
    repo: str | Path,
    query: str,
    results: list[Any],
    *,
    successful_only: bool,
    limit: int,
    min_score: float | None,
    model: str | None,
) -> None:
    """Emit ``SearchResult`` rows next to the filters that produced them.

    Echoing the filters is what makes the object reproducible: ``count`` capped at
    ``limit`` is otherwise indistinguishable from a repository that held no more.
    """
    emit(
        {
            "command": "repo-search",
            "repo": str(repo),
            "query": query,
            "successful_only": successful_only,
            "limit": limit,
            "min_score": min_score,
            "model": model,
            "count": len(results),
            "results": [asdict(result) for result in results],
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
