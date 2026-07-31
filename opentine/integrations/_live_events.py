"""Turning one live callback span into a TraceEvent the store will accept.

Everything a framework hands a callback is untrusted text: a tool result sliced
mid-emoji, a metadata dict copied out of a JSON body, a run name built from a
provider response. All of it reaches an immutable v3 object, and the v3 objects
are UTF-8 JSON -- a str holding an unpaired UTF-16 surrogate has no UTF-8
spelling at all, so ``repo.put`` refuses it.

That refusal arrives at *flush* time, inside ``Recorder.import_events``, which
stores a batch whole or not at all. One bad character in one attribute would
therefore destroy an agent run that had already completed successfully, which is
the opposite of what a provenance tool is for. So every field is confined here,
before the event exists:

* ``inputs``/``outputs`` are blob-bound, and run through the very gate the
  recorder will apply (:func:`storable`); a refused payload becomes a note;
* ``actor``/``model``/span ids are plain strings and are respelled with their
  escapes (:func:`storable_text`) -- lossless, and the run survives;
* ``attributes`` are arbitrary nested framework metadata and are walked
  (:func:`storable_attributes`), flagged in band when anything was respelled.

The loss stays confined to the field that caused it. Nothing here mutates the
callback -> TraceEvent mapping itself; it only makes that mapping total.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any

from opentine._blob_guard import guarded_blob_body
from opentine._jsonsafe import json_safe
from opentine._unicode_text import SURROGATE_CHAR, lone_surrogate_path
from opentine.trace._import_helpers import imported_usage
from opentine.trace.schema import TraceEvent

UNSTORABLE = "opentine.unstorable"
MAX_RECORDED_ERRORS = 50


def capture_note(
    events: list[TraceEvent], dropped: int, errors: list[str], timestamp: float
) -> TraceEvent | None:
    """The in-band record of capture loss, so an incomplete run says so itself."""
    if not dropped and not errors:
        return None
    return TraceEvent(
        kind="error",
        timestamp=timestamp,
        trace_id=events[0].trace_id if events else "opentine",
        span_id=f"opentine-capture-{uuid.uuid4()}",
        actor="opentine.capture",
        outputs={"dropped_events": dropped, "errors": errors[:MAX_RECORDED_ERRORS]},
        attributes={"framework": "opentine", "opentine.capture_incomplete": True},
    )


def storable(value: Any, where: str) -> dict[str, Any]:
    """Coerce one blob-bound payload, substituting a note when it cannot be stored.

    ``Recorder.import_events`` writes every input/output through
    ``guarded_blob_body``. A payload that gate refuses would fail the *whole*
    batch at flush time and lose an agent run that already completed, so the same
    gate runs here, per field: the loss stays confined to the one payload that
    caused it and the rest of the run is still recorded.
    """
    safe = json_safe(value if isinstance(value, dict) else {"value": value})
    if not isinstance(safe, dict):  # a mapping whose keys collided after coercion
        safe = {"value": safe}
    try:
        guarded_blob_body(safe)
    except (ValueError, RecursionError) as exc:
        return {UNSTORABLE: f"{where}: {type(exc).__name__}: {exc}"[:2000]}
    return safe


def storable_text(value: Any) -> str:
    """Spell a string the v3 objects cannot carry as its escapes instead of raising.

    Only a lone surrogate is rewritten, and it is rewritten to the exact escape
    ``opentine._unicode_text`` uses when it names one in a refusal, so the
    recorded text still says which code unit arrived. Legal text -- every actor
    name, model name and span id in an ordinary run -- is returned untouched.
    """
    text = str(value)
    if SURROGATE_CHAR.search(text) is None:
        return text
    return text.encode("utf-8", "backslashreplace").decode("utf-8")


def _respelled(value: Any) -> Any:
    """``storable_text`` over an already ``json_safe`` structure, keys included.

    Written as statements rather than comprehensions, like ``json_safe`` itself:
    recursion inside a comprehension costs an extra frame per nesting level
    before 3.12, which would make the depth this walk survives depend on the
    interpreter running it.
    """
    if isinstance(value, str):
        return storable_text(value)
    if isinstance(value, dict):
        mapped: dict[str, Any] = {}
        for name, item in value.items():
            mapped[storable_text(name)] = _respelled(item)
        return mapped
    if isinstance(value, list):
        items = []
        for item in value:
            items.append(_respelled(item))
        return items
    return value


def storable_attributes(attributes: Any, where: str) -> dict[str, Any]:
    """Confine unstorable text anywhere in a span's attributes.

    Attributes are the one field carried into the event object verbatim rather
    than through the blob gate, and they are also the field a framework fills
    straight from its own metadata -- so this is where untrusted text most often
    arrives. The whole structure is walked only when the cheap surrogate scan
    says there is something to find.
    """
    safe = json_safe(attributes)
    if not isinstance(safe, dict):
        safe = {"value": safe}
    if lone_surrogate_path(safe) is None:
        return safe
    guarded: dict[str, Any] = dict(_respelled(safe))
    guarded[UNSTORABLE] = f"{where}: unpaired UTF-16 surrogate spelled as its escape"
    return guarded


@dataclass
class LiveSpan:
    """One in-flight unit of framework work, before it becomes a TraceEvent."""

    span_id: str
    trace_id: str
    parent_span_id: str | None = None
    kind: str = "model"
    actor: str = ""
    model: str = ""
    inputs: dict[str, Any] = field(default_factory=dict)
    outputs: dict[str, Any] = field(default_factory=dict)
    usage: dict[str, Any] = field(default_factory=dict)
    attributes: dict[str, Any] = field(default_factory=dict)
    started: float = 0.0
    ended: float | None = None

    def event(self) -> TraceEvent:
        end = self.started if self.ended is None else self.ended
        # imported_usage is the same normalizer the post-hoc importers use, so a
        # usage dimension a framework reports oddly is dropped (and reported in
        # attributes) identically on both paths.
        usage, attributes = imported_usage(self.usage, json_safe(dict(self.attributes)))
        return TraceEvent(
            kind=self.kind,
            timestamp=self.started,
            trace_id=self.trace_id,
            span_id=self.span_id,
            parent_span_id=self.parent_span_id,
            actor=storable_text(self.actor),
            model=storable_text(self.model),
            duration=max(0.0, end - self.started),
            inputs=storable(self.inputs, "inputs"),
            outputs=storable(self.outputs, "outputs"),
            usage=usage,
            attributes=storable_attributes(attributes, "attributes"),
        )


def apply_fields(span: LiveSpan, fields: dict[str, Any]) -> None:
    for name, value in fields.items():
        if value is None or not hasattr(span, name):
            continue
        current = getattr(span, name)
        if isinstance(current, dict) and isinstance(value, dict):
            current.update(value)
        else:
            setattr(span, name, value)
