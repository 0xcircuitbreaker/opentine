"""0.33: ``tine fork --ref ... --set/--unset/--edit-file`` on a repository run.

The repository twin of :mod:`opentine._fork_edit`. ``Repo.fork`` builds the
forked payload as always; with an ``edit`` override the fork-point event is then
swapped for an edited copy whose result is cleared (it was never executed), and
the change log -- each path with the SHA-256 of its old and new value, exactly
the record a ``.tine`` fork keeps in ``metadata["edit"]`` -- goes into the run's
``fork_overrides``. The run oid covers that payload, so it binds the edit. A fork
without an ``edit`` override never reaches this module and hashes as before.
"""

from __future__ import annotations

import copy
from typing import TYPE_CHECKING, Any

from opentine._canon import _redact
from opentine._fork_edit import UNSET, edit_fields
from opentine._graph_types import StepKind, step_id
from opentine._jsonsafe import json_stored
from opentine._unicode_text import assert_unicode_text
from opentine.repository._prompt_parts import join_inputs, put_event_inputs
from opentine.repository._run_blobs import blob_json, json_blob, put_transcript, transcript_blob

if TYPE_CHECKING:
    from opentine.repository.store import Repo

_CLEARED = {"billing": {}, "cost": 0.0, "duration": 0.0, "error": {}, "usage": {}}
_SHAPE = "fork edit override must be a non-empty list of (path, value)"


def check_edits(value: Any) -> list[tuple[str, Any]]:
    """The ``edit`` override: a non-empty list of ``(path, value)`` pairs."""
    if not isinstance(value, list | tuple) or not value:
        raise ValueError(_SHAPE)
    edits = []
    for item in value:
        if not isinstance(item, list | tuple) or len(item) != 2 or not isinstance(item[0], str):
            raise ValueError(_SHAPE)
        edits.append((item[0], item[1]))
    shown = [[path, None if new is UNSET else new] for path, new in edits]
    assert_unicode_text(_redact(json_stored(shown, "fork edit")), where="fork edit")
    return edits


def _legacy_id(repo: Repo, event: dict[str, Any], fields: dict[str, Any]) -> str:
    """The ``.tine`` step id the edited step would have, or "" when it cannot be named."""
    parents = [repo.get(oid).payload().get("legacy_step_id") for oid in event["parent_ids"]]
    kind = str(event.get("kind", ""))
    named = all(isinstance(p, str) and p and not p.startswith("event:") for p in parents)
    if kind not in StepKind._value2member_map_ or not named:
        return ""
    return step_id(
        StepKind(kind), fields["inputs"], parent_ids=parents,
        model_info=fields["model_info"], tool_info=fields["tool_info"],
    )  # fmt: skip


def _edited_event(repo: Repo, point: str, edits: list[tuple[str, Any]]) -> tuple[str, list]:
    event = dict(repo.get(point).payload())
    event["parent_ids"] = list(event.get("parent_ids") or [])
    inputs = blob_json(repo, event["input_blob"]) if event.get("input_blob") else {}
    inputs = join_inputs(inputs, event, lambda oid: blob_json(repo, oid))
    fields = {"inputs": inputs, "model_info": event.get("model") or "",
              "tool_info": dict(event.get("tool") or {})}  # fmt: skip
    before = copy.deepcopy(fields)
    changes = edit_fields(fields, edits)
    if fields == before:
        raise ValueError("The edit changes nothing: step K already holds these values")
    event.pop("provider", None)
    put_event_inputs(event, fields["inputs"], lambda value: json_blob(repo, value))
    event.update(_CLEARED, output_blob=json_blob(repo, {}), model=fields["model_info"],
                 tool=_redact(fields["tool_info"]))  # fmt: skip
    if legacy := _legacy_id(repo, event, fields):
        event["legacy_step_id"] = legacy
    else:
        event.pop("legacy_step_id", None)
    return repo.put("event", json_stored(event, "event")), changes


def apply_event_edit(
    repo: Repo, forked: dict[str, Any], point: str, edits: list[tuple[str, Any]]
) -> None:
    """Swap ``point`` in the ``forked`` payload for its edited copy, in place."""
    new, changes = _edited_event(repo, point, edits)
    for field in ("events", "roots", "tips"):
        forked[field] = [new if item == point else item for item in forked.get(field) or []]
    refs = forked.get("legacy_refs") or {}
    forked["legacy_refs"] = {name: new if ref == point else ref for name, ref in refs.items()}
    manifests = forked.get("manifests") or {}
    if transcript := manifests.get("transcript"):
        # Step K's own entries recorded the call the edit replaced; they go.
        kept = [
            item
            for item in transcript_blob(repo, transcript)
            if not (isinstance(item, dict) and item.get("step_id") == point)
        ]
        manifests["transcript"] = put_transcript(repo, kept, {e: e for e in forked["events"]})
    forked["fork_overrides"]["edit"] = {
        "step": point,
        "edited_step": new,
        "changes": changes,
        "executed": False,
    }
