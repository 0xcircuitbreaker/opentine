"""``parents``: a run's parent runs, the first step towards merge (F2, 0.43).

``parents`` is an optional run field: a non-empty list of unique **run** oids,
each a link (``kernel.validate_links``), so ``fsck``, ``gc`` and transfer keep
the parent runs. A writer **omits** it when there are none -- it never writes
``"parents": []`` -- so every run written before 0.43, and every run without
parents after it, keeps exactly the oid it had. ``forked_from`` stays what it
was (the run a fork or resume continues); ``parents`` names the runs a merge
combined. Merge itself is 0.45+ (``docs/design/F2-merge.md``).
"""

from __future__ import annotations

from typing import Any

from opentine.kernel import KernelError, parse_oid

FIELD = "parents"
MAX_PARENTS = 64


def validate_parents(payload: dict[str, Any]) -> None:
    """Refuse a malformed ``parents`` (absent is always fine)."""
    if FIELD not in payload:
        return
    parents = payload[FIELD]
    if (
        type(parents) is not list
        or not 1 <= len(parents) <= MAX_PARENTS
        or len(set(parents)) != len(parents)
        or any(parse_oid(parent)[0] != "run" for parent in parents)
    ):
        raise KernelError("parents must be a non-empty list of unique run ids (omit when none)")


def set_parents(payload: dict[str, Any], parents: list[str] | tuple[str, ...]) -> None:
    """Set *payload*'s ``parents``, or remove the field when *parents* is empty."""
    rows = list(dict.fromkeys(parents))
    if rows:
        payload[FIELD] = rows
        validate_parents(payload)
    else:
        payload.pop(FIELD, None)


def run_parents(payload: Any) -> list[str]:
    """The parent runs a run payload names (``[]`` when it names none)."""
    value = payload.get(FIELD) if isinstance(payload, dict) else None
    return list(value) if isinstance(value, list) else []


def set_run_parents(run: Any, parents: list[str] | tuple[str, ...]) -> None:
    """Have the next ``put_run`` of *run* record *parents* (empty: none)."""
    run.parents = list(parents)


__all__ = ["FIELD", "run_parents", "set_parents", "set_run_parents", "validate_parents"]
