"""Which memory notes a run was served, recorded when it was captured (0.61).

A memory note that reaches an agent's context is recorded in the consuming
run's own step evidence, at the moment it is served: one ``tool`` event whose
``attributes`` hold :data:`ATTRIBUTE` (the sorted note digests, the blob oids
of the signed notes) and whose ``inputs`` hold the recall query. The event is
an ordinary step of the run, so it is content addressed with the rest of it.

Recording happens only while the run is still being captured: a run that is
finished (``completed`` or ``failed``) or already has an attestation is never
amended, so a run cannot be said, after the fact, to have been served a note
it never saw (or not to have been served one it saw). :func:`served` reads the
digests back from a run's events.

``--min-assurance`` ranks a note by the run it is about (its ``subject``): the
tier that run's capture claims (:mod:`opentine._assurance`), capped at ``T1``
because a stored run carries no proxy witness to check here, and ``T0`` for a
note with no subject run, or whose subject run is not stored.
"""

from __future__ import annotations

import secrets
import time
from typing import Any

ATTRIBUTE = "opentine.memory.served"
TOOL = "memory.recall"
ACTOR = "tine-memory"
FINISHED = frozenset({"completed", "failed"})
MAX_SERVED = 50


class ServedError(ValueError):
    """The served notes cannot be recorded in this run."""


def _event(digests: list[str], query: str) -> Any:
    from opentine.trace.schema import TraceEvent

    return TraceEvent(kind="tool", timestamp=time.time(), trace_id=secrets.token_hex(16),
                      span_id=secrets.token_hex(8), actor=ACTOR,
                      inputs={"tool": TOOL, "query": query},
                      outputs={"served": digests},
                      attributes={ATTRIBUTE: digests})  # fmt: skip


def _digests(rows: list[dict[str, Any]]) -> list[str]:
    found = sorted({str(row["digest"]) for row in rows})
    if len(found) > MAX_SERVED:
        raise ServedError(f"at most {MAX_SERVED} notes are recorded per step")
    return found


def record(repo: Any, run_or_ref: str, rows: list[dict[str, Any]], query: str) -> str | None:
    """Append the served step to the run being captured; the new run oid (``None``: none served)."""
    from opentine.trace.recorder import Recorder

    digests = _digests(rows)
    if not digests:
        return None
    recorder = Recorder.resume(repo, run_or_ref)
    payload = recorder.payload
    if payload.get("status") in FINISHED:
        raise ServedError(
            f"{recorder.run_id} is {payload['status']}: a finished run is not amended"
        )
    if repo.attestations_for(recorder.run_id):
        raise ServedError(f"{recorder.run_id} is attested: a signed run is not amended")
    recorder.append(_event(digests, query))
    return recorder.run_id


def record_with(recorder: Any, rows: list[dict[str, Any]], query: str) -> str | None:
    """In-process capture: append the served step to *recorder*'s run; its event id."""
    digests = _digests(rows)
    return recorder.append(_event(digests, query)) if digests else None


def event_served(payload: Any) -> list[str]:
    """The note digests an event payload records as served (empty when none)."""
    attributes = payload.get("attributes") if isinstance(payload, dict) else None
    value = attributes.get(ATTRIBUTE) if isinstance(attributes, dict) else None
    if not isinstance(value, list):
        return []
    return sorted({v for v in value if isinstance(v, str) and v.startswith("blob:sha256:")})


def served(repo: Any, run: str) -> list[str]:
    """Every note digest *run*'s events record as served."""
    payload = repo.get(run).payload()
    found: set[str] = set()
    for event in payload.get("events") or []:
        try:
            found.update(event_served(repo.get(event).payload()))
        except (KeyError, ValueError, OSError):
            continue
    return sorted(found)


def assurance(repo: Any, subject: Any) -> str:
    """The tier of a note whose subject is *subject* (see the module docstring)."""
    from opentine._assurance import CLAIM_ATTRIBUTE, HOOK_ATTRIBUTE, TIERS

    if not isinstance(subject, str) or not subject.startswith("run:"):
        return "T0"
    try:
        payload = repo.get(subject).payload()
    except (KeyError, ValueError, OSError):
        return "T0"
    metadata = payload.get("metadata") if isinstance(payload, dict) else None
    capture = metadata.get("capture") if isinstance(metadata, dict) else None
    if isinstance(capture, dict) and capture.get("claimed_tier") in TIERS[1:]:
        return "T1"
    for event in (payload.get("events") or [])[:64]:
        try:
            attributes = repo.get(event).payload().get("attributes") or {}
        except (KeyError, ValueError, OSError, AttributeError):
            continue
        if attributes.get(CLAIM_ATTRIBUTE) == "T1" or HOOK_ATTRIBUTE in attributes:
            return "T1"
    return "T0"


def at_least(repo: Any, rows: list[dict[str, Any]], tier: str | None) -> list[dict[str, Any]]:
    """*rows* (recall rows) whose note's tier is at least *tier*, each with ``assurance``."""
    from opentine._assurance import TIERS, rank

    if tier is not None and tier not in TIERS:
        raise ValueError(f"--min-assurance is one of {', '.join(TIERS)}")
    out = []
    for row in rows:
        found = assurance(repo, row.get("subject"))
        if tier is None or rank(found) >= rank(tier):
            out.append({**row, "assurance": found})
    return out


__all__ = ["ATTRIBUTE", "ServedError", "assurance", "at_least", "event_served", "record",
           "record_with", "served"]  # fmt: skip
