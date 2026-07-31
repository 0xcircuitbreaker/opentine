"""Framework-agnostic accumulation of live callback spans into one v3 run.

Every callback-driven agent framework reports work the same way: a *start* and
an *end* keyed by an opaque run id, with a parent run id naming the enclosing
unit. That is already the shape of :class:`~opentine.trace.schema.TraceEvent` --
and the shape :func:`opentine.trace.importers.framework_events` reconstructs
*after* the fact from a serialized log. This module is the live half of the same
mapping: it holds the open spans, turns each closed span into a TraceEvent (in
:mod:`opentine.integrations._live_events`, which also confines any text the
store would refuse), and materializes the accumulated events through
:class:`~opentine.trace.recorder.Recorder`. The live path and the post-hoc path
therefore converge on one schema and one recorder rather than forking the model.

Nothing here knows about any particular framework, which is deliberate: it is
the seam a second adapter plugs into. Translating another framework's events
into :meth:`LiveRun.open` / :meth:`LiveRun.close` / :meth:`LiveRun.mark` calls is
the whole job -- the recording half is already written and tested.

A run is created lazily, at the first span, and finalized when the last open
span closes, so an unused handler never writes to the repository and a completed
agent invocation lands as one ordinary run with ``status`` ``completed`` or
``failed``.

The recording half's one hard rule: **a live run is never lost in the whole.**
Whatever a framework does -- overrun the recorder's event cap, repeat a run id,
hand over text no UTF-8 store can hold -- the outcome is a finalized run saying
in band what it could not keep, never a stuck ``running`` run holding nothing.
Every guard below serves that rule, and :meth:`LiveRun.flush` contains whatever
the guards did not anticipate.
"""

from __future__ import annotations

import time
from dataclasses import replace
from typing import Any

from opentine.integrations._live_events import (
    LiveSpan,
    apply_fields,
    capture_note,
    storable_text,
)
from opentine.trace.recorder import MAX_RECORDED_EVENTS, Recorder
from opentine.trace.schema import TraceEvent

DEFAULT_REF = "heads/main"
#: Deliberately *one below* the recorder's own cap: ``import_events`` refuses an
#: oversized batch whole, and a full live run appends one more event at flush --
#: the capture-loss note. Capturing MAX_RECORDED_EVENTS spans would submit a
#: batch of cap + 1 and lose the whole run the moment it finished.
MAX_LIVE_EVENTS = MAX_RECORDED_EVENTS - 1


class LiveRun:
    """Open spans, the events they closed into, and the recorder that stores them."""

    def __init__(
        self,
        repo: Any,
        *,
        ref: str = DEFAULT_REF,
        prompt: str = "",
        system: str = "",
        capture: bool = False,
        max_events: int = MAX_LIVE_EVENTS,
        clock: Any = time.time,
    ) -> None:
        self.repo = repo
        self.ref = ref
        self.prompt = prompt
        self.system = system
        self.capture = capture
        # Clamped, not trusted: a caller asking for the recorder's whole budget
        # must still leave room for the note that says events were dropped.
        self.max_events = max(1, min(int(max_events), MAX_LIVE_EVENTS))
        self.clock = clock
        self.events: list[TraceEvent] = []
        self.errors: list[str] = []
        self.dropped = 0
        self.run_id: str | None = None
        self.run_ids: list[str] = []
        self._open: dict[str, LiveSpan] = {}
        self._traces: dict[str, str] = {}
        self._seen: set[tuple[str, str]] = set()
        self._repeats = 0
        self._recorder: Recorder | None = None
        self._failed = False

    @property
    def open_spans(self) -> int:
        return len(self._open)

    def _span(self, span_id: Any, parent_span_id: Any, fields: dict[str, Any]) -> LiveSpan:
        if self._recorder is None:
            self._recorder = Recorder.start(
                self.repo,
                ref=self.ref,
                prompt=self.prompt,
                system=self.system,
                capture=self.capture,
            )
            self.run_id = self._recorder.run_id
        # Span ids are respelled here rather than at event time so that open,
        # update, close and the parent lookups all agree on one key.
        key = storable_text(span_id)
        parent = None if parent_span_id in (None, "") else storable_text(parent_span_id)
        # A span inherits its root's trace id; a parentless span (or one whose
        # parent was never seen, because the handler attached mid-run) starts a
        # trace of its own rather than silently joining an unrelated one.
        self._traces[key] = trace = (parent and self._traces.get(parent)) or key
        return LiveSpan(
            span_id=key,
            trace_id=trace,
            parent_span_id=parent,
            started=self.clock(),
            **fields,
        )

    def open(self, span_id: Any, parent_span_id: Any = None, **fields: Any) -> LiveSpan:
        span = self._span(span_id, parent_span_id, fields)
        self._open[span.span_id] = span
        return span

    def update(self, span_id: Any, **fields: Any) -> LiveSpan | None:
        span = self._open.get(storable_text(span_id))
        if span is not None and fields:
            apply_fields(span, fields)
        return span

    def close(self, span_id: Any, **fields: Any) -> LiveSpan | None:
        span = self._open.pop(storable_text(span_id), None)
        if span is None:
            return None
        apply_fields(span, fields)
        span.ended = self.clock()
        self._emit(span)
        if not self._open:
            self.flush()
        return span

    def mark(self, span_id: Any, parent_span_id: Any = None, **fields: Any) -> LiveSpan:
        """Record an instantaneous event, for a callback with no start/end pair."""
        span = self._span(span_id, parent_span_id, fields)
        span.ended = span.started
        self._emit(span)
        # A run made only of marks -- a handler that attached mid-run and saw one
        # on_*_error for a start it never got, or a lone agent decision -- has no
        # span left to close, so this is its last chance to finalize. With an
        # enclosing span still open (the ordinary case: an agent action under its
        # chain) nothing happens here and the close finalizes as usual.
        if not self._open:
            self.flush()
        return span

    def mark_failed(self) -> None:
        self._failed = True

    def _emit(self, span: LiveSpan) -> None:
        if len(self.events) >= self.max_events:
            self.dropped += 1
            return
        try:
            self.events.append(self._unique(span.event()))
        except (ValueError, RecursionError) as exc:
            self.errors.append(f"{span.span_id}: {type(exc).__name__}: {exc}"[:500])

    def _unique(self, event: TraceEvent) -> TraceEvent:
        """Rename a span id this run already used instead of letting it kill the run.

        A framework may report the same run id twice -- a retried or restarted
        span, an error whose start arrived late -- and the recorder refuses a
        repeated (trace, span) pair for the whole batch. The repeat is kept under
        a suffixed id naming the original in band, so it is still evidence.
        """
        key = (event.trace_id, event.span_id)
        if key not in self._seen:
            self._seen.add(key)
            return event
        span_id = event.span_id
        while (event.trace_id, span_id) in self._seen:
            self._repeats += 1
            span_id = f"{event.span_id}#{self._repeats}"
        self._seen.add((event.trace_id, span_id))
        attributes = {**event.attributes, "opentine.duplicate_span_id": event.span_id}
        return replace(event, span_id=span_id, attributes=attributes)

    def _note(self, events: list[TraceEvent]) -> TraceEvent | None:
        while events and len(events) >= MAX_RECORDED_EVENTS:  # room for the note itself
            events.pop()
            self.dropped += 1
        note = capture_note(events, self.dropped, self.errors, self.clock())
        self.dropped, self.errors = 0, []
        return note

    def flush(self, status: str | None = None) -> str | None:
        """Materialize everything accumulated so far as one finalized run."""
        for span in self._open.values():  # an explicit flush mid-run keeps the truth
            span.attributes["opentine.incomplete"] = True
            span.ended = self.clock()
            self._emit(span)
        self._open.clear()
        self._traces.clear()
        self._seen.clear()
        self._repeats = 0
        recorder, self._recorder = self._recorder, None
        events, self.events = self.events, []
        if recorder is None:
            return None
        self._materialize(recorder, events)
        resolved = status or ("failed" if self._failed else "completed")
        self._failed = False
        self.run_id = self._finalized(recorder, resolved)
        self.run_ids.append(self.run_id)
        return self.run_id

    def _materialize(self, recorder: Recorder, events: list[TraceEvent]) -> None:
        """Store the batch, degrading to a note rather than losing the run.

        ``import_events`` rejects a batch whole, so an edge no guard above
        anticipated would leave a finished agent invocation as an empty
        ``running`` run -- the worst outcome a provenance tool has. The known
        edges are guarded earlier; this contains the rest, and the run is
        finalized either way with an in-band record of what it cost.
        """
        note = self._note(events)
        if note is not None:
            events.append(note)
        if not events:
            return
        try:
            recorder.import_events(events)
            return
        except (ValueError, RecursionError) as exc:
            self.dropped += len(events)
            self.errors.append(f"import_events: {type(exc).__name__}: {exc}"[:500])
        loss = self._note([])
        if loss is not None:
            try:
                recorder.import_events([loss])
            except (ValueError, RecursionError):  # the store itself refused; finalize anyway
                pass

    @staticmethod
    def _finalized(recorder: Recorder, status: str) -> str:
        try:
            return recorder.finalize(status)
        except (ValueError, RecursionError):
            return recorder.run_id  # the events landed; only the status write did not
