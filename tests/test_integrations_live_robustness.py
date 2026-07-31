"""Live capture must never lose a run in the whole.

Every test here reproduces a defect that cost an *entire* finished agent run:
the callbacks arrived, the invocation completed, and the repository was left
holding a stuck, empty ``running`` run because one refusal at flush time
rejected the whole batch. The fix in each case is a bounded, in-band
degradation -- some events, plus a recorded note saying what was lost -- so
these tests pin the floor: after any of these runs the repository holds a
*finalized* run, never a stuck one.

Nothing here shells a binary and nothing needs langchain installed: the
handler's callbacks are driven directly with the argument shapes langchain-core
uses, exactly as in ``tests/test_integrations_langchain.py``.
"""

from __future__ import annotations

import json
import uuid
from types import SimpleNamespace

import pytest

from opentine.integrations import _live_spans
from opentine.integrations._live_spans import MAX_LIVE_EVENTS, LiveRun
from opentine.integrations.langchain import OpenTineCallbackHandler
from opentine.repository import Repo
from opentine.trace import recorder as recorder_module
from opentine.trace.recorder import MAX_RECORDED_EVENTS, Recorder

CHAIN, MODEL, TOOL = (uuid.UUID(int=index) for index in (1, 2, 3))


def _action(tool: str = "moons") -> SimpleNamespace:
    return SimpleNamespace(tool=tool, tool_input={"planet": "mars"}, log="thinking")


def _read(repo: Repo, event: dict) -> dict:
    event = dict(event)
    event["read_outputs"] = json.loads(repo.get(event["output_blob"]).body)
    return event


def _stored(repo: Repo, run_id: str | None) -> tuple[dict, dict[str, dict]]:
    """The run payload plus its events, keyed by span id."""
    assert run_id is not None
    payload = repo.get(run_id).payload()
    events = [_read(repo, repo.get(oid).payload()) for oid in payload["events"]]
    return payload, {event["span_id"]: event for event in events}


def _notes(events: dict[str, dict]) -> list[dict]:
    return [event for event in events.values() if event["actor"] == "opentine.capture"]


def _handler(tmp_path, **options) -> tuple[Repo, OpenTineCallbackHandler]:
    repo = Repo.init(tmp_path)
    return repo, OpenTineCallbackHandler(repo, capture=False, **options)


# -- 1. the event cap ---------------------------------------------------------


def test_the_live_cap_reserves_room_for_the_capture_note():
    """Capturing the recorder's whole budget submits a batch of cap + 1 events.

    ``Recorder.import_events`` refuses an oversized batch *whole*, so a live cap
    equal to the recorder's cap lost every event of an oversized run, not the
    overflow. The live cap is therefore one lower, and a caller cannot raise it.
    """
    assert MAX_LIVE_EVENTS == MAX_RECORDED_EVENTS - 1
    assert LiveRun(None).max_events == MAX_LIVE_EVENTS
    assert LiveRun(None, max_events=MAX_RECORDED_EVENTS).max_events == MAX_LIVE_EVENTS
    assert LiveRun(None, max_events=10**9).max_events == MAX_LIVE_EVENTS


def test_a_run_over_the_cap_records_its_bounded_prefix(tmp_path, monkeypatch):
    """The same overflow at a scaled-down cap, end to end through the handler."""
    monkeypatch.setattr(recorder_module, "MAX_RECORDED_EVENTS", 12)
    monkeypatch.setattr(_live_spans, "MAX_LIVE_EVENTS", 11)
    repo, handler = _handler(tmp_path, max_events=12)

    handler.on_chain_start({"name": "agent"}, {"q": 1}, run_id=CHAIN)
    for index in range(30):
        tool = uuid.UUID(int=100 + index)
        handler.on_tool_start({"name": "moons"}, "{}", run_id=tool, parent_run_id=CHAIN)
        handler.on_tool_end(str(index), run_id=tool, parent_run_id=CHAIN)
    handler.on_chain_end({"output": "done"}, run_id=CHAIN)

    payload, events = _stored(repo, handler.run_id)
    assert payload["status"] == "completed"  # not a stuck, empty "running" run
    assert len(payload["events"]) == 12  # the recorder's cap, note included
    assert str(uuid.UUID(int=100)) in events  # the prefix is present ...
    assert str(uuid.UUID(int=129)) not in events  # ... and the overflow is not
    notes = _notes(events)
    assert len(notes) == 1
    # 30 tools + the enclosing chain, of which 11 fit under the live cap
    assert notes[0]["read_outputs"]["dropped_events"] == 31 - 11


def test_a_run_past_the_real_event_cap_is_bounded_not_lost(tmp_path):
    """The unscaled reproduction: >3000 spans used to record nothing at all.

    Deliberately expensive -- it writes the recorder's full event budget -- but
    it is the only test that runs the shipped constants against the shipped
    store, which is exactly where the whole-run loss happened.
    """
    repo, handler = _handler(tmp_path)
    spans = MAX_RECORDED_EVENTS + 100

    handler.on_chain_start({"name": "agent"}, {"q": 1}, run_id=CHAIN)
    for _ in range(spans):  # marks are one event each: the cheapest oversized run
        handler.on_agent_action(_action(), run_id=CHAIN)
    handler.on_chain_end({"output": "done"}, run_id=CHAIN)

    assert handler.run_id is not None and handler.run_ids == [handler.run_id]
    payload = repo.get(handler.run_id).payload()
    assert payload["status"] == "completed"
    assert len(payload["events"]) == MAX_RECORDED_EVENTS
    first = _read(repo, repo.get(payload["events"][0]).payload())
    assert first["span_id"] == f"{CHAIN}:agent_action:1"  # the bound keeps the prefix
    tail = [_read(repo, repo.get(oid).payload()) for oid in payload["events"][-3:]]
    notes = [event for event in tail if event["actor"] == "opentine.capture"]
    assert len(notes) == 1
    assert notes[0]["attributes"]["opentine.capture_incomplete"] is True
    assert notes[0]["read_outputs"]["dropped_events"] == spans + 1 - MAX_LIVE_EVENTS


# -- 2. text the store cannot hold --------------------------------------------


def test_a_lone_surrogate_in_metadata_does_not_destroy_the_run(tmp_path):
    """Attributes come straight from framework metadata and bypass the blob gate."""
    repo, handler = _handler(tmp_path)
    handler.on_chain_start(
        {"name": "agent"},
        {"q": 1},
        run_id=CHAIN,
        metadata={"note": "\ud800", "nested": {"\ud800key": ["ok", "x\udfff"]}, "kept": True},
    )
    handler.on_chain_end({"output": "ok"}, run_id=CHAIN)

    payload, events = _stored(repo, handler.run_id)
    assert payload["status"] == "completed"
    attributes = events[str(CHAIN)]["attributes"]
    assert attributes["note"] == "\\ud800"  # respelled as the escape, not dropped
    assert attributes["nested"] == {"\\ud800key": ["ok", "x\\udfff"]}
    assert attributes["kept"] is True and attributes["framework"] == "langchain"
    assert "opentine.unstorable" in attributes
    assert events[str(CHAIN)]["read_outputs"] == {"output": "ok"}


def test_a_lone_surrogate_in_an_actor_or_span_id_does_not_destroy_the_run(tmp_path):
    """``actor``, ``model`` and the span ids are written into the event verbatim."""
    repo, handler = _handler(tmp_path)
    handler.on_chain_start({"name": "agent"}, {"q": 1}, run_id=CHAIN)
    handler.on_tool_start({"name": "moons\ud800"}, "{}", run_id="tool-\ud800", parent_run_id=CHAIN)
    handler.on_tool_end("2", run_id="tool-\ud800", parent_run_id=CHAIN)
    handler.on_chain_end({"output": "ok"}, run_id=CHAIN)

    payload, events = _stored(repo, handler.run_id)
    assert payload["status"] == "completed"
    tool = events["tool-\\ud800"]
    assert tool["actor"] == "moons\\ud800"
    assert tool["read_outputs"] == {"output": "2"}
    assert tool["trace_id"] == str(CHAIN)  # respelling the id kept the parentage
    assert set(events) == {str(CHAIN), "tool-\\ud800"}


# -- 3. a span id a framework reports twice -----------------------------------


def test_a_repeated_span_id_is_suffixed_rather_than_fatal(tmp_path):
    """A retried span reuses its run id; the recorder refuses a repeated pair."""
    repo, handler = _handler(tmp_path)
    handler.on_chain_start({"name": "agent"}, {"q": 1}, run_id=CHAIN)
    for attempt in ("first", "second"):
        handler.on_tool_start({"name": "moons"}, "{}", run_id=TOOL, parent_run_id=CHAIN)
        handler.on_tool_end(attempt, run_id=TOOL, parent_run_id=CHAIN)
    handler.on_chain_end({"output": "ok"}, run_id=CHAIN)

    payload, events = _stored(repo, handler.run_id)
    assert payload["status"] == "completed"
    assert events[str(TOOL)]["read_outputs"] == {"output": "first"}
    repeat = events[f"{TOOL}#1"]
    assert repeat["read_outputs"] == {"output": "second"}
    assert repeat["attributes"]["opentine.duplicate_span_id"] == str(TOOL)


def test_an_error_arriving_after_its_span_closed_is_still_recorded(tmp_path):
    """The same collision the other way round: a late error for a closed span.

    ``_fail`` records an error whose start it never saw as an instantaneous
    event under the run id itself -- which is the id the closed span already
    used, so the second arrival repeats a (trace, span) pair the recorder holds.
    """
    repo, handler = _handler(tmp_path)
    handler.on_chain_start({"name": "agent"}, {"q": 1}, run_id=CHAIN)
    handler.on_tool_start({"name": "moons"}, "{}", run_id=TOOL)  # parentless sibling
    handler.on_tool_end("2", run_id=TOOL)
    handler.on_tool_error(RuntimeError("late"), run_id=TOOL)
    handler.on_chain_end({"output": "ok"}, run_id=CHAIN)

    payload, events = _stored(repo, handler.run_id)
    assert payload["status"] == "failed"
    assert events[str(TOOL)]["read_outputs"] == {"output": "2"}
    late = events[f"{TOOL}#1"]
    assert late["kind"] == "error" and late["read_outputs"]["error"] == "late"
    assert late["attributes"]["opentine.duplicate_span_id"] == str(TOOL)


# -- 4. per-run state on a long-lived handler ---------------------------------


def test_mark_state_is_released_and_renumbered_for_each_invocation(tmp_path):
    """One handler is normally reused for the life of an application."""
    repo, handler = _handler(tmp_path)
    for _ in range(3):  # a framework that reuses run ids across invocations
        handler.on_chain_start({"name": "agent"}, {"q": 1}, run_id=CHAIN)
        handler.on_agent_action(_action(), run_id=CHAIN)
        handler.on_agent_finish(SimpleNamespace(return_values={"o": 1}, log="done"), run_id=CHAIN)
        handler.on_chain_end({"output": "ok"}, run_id=CHAIN)

    assert len(handler.run_ids) == 3
    assert len(handler._marks) <= 2  # bounded: the run in flight only
    for run_id in handler.run_ids:
        _, events = _stored(repo, run_id)
        assert f"{CHAIN}:agent_action:1" in events  # never :2 or :3
        assert f"{CHAIN}:agent_finish:1" in events


# -- 5. a run made only of marks ----------------------------------------------


def test_a_run_of_marks_alone_finalizes(tmp_path):
    """A handler attached mid-run sees an error for a start it never got."""
    repo, handler = _handler(tmp_path)
    handler.on_llm_error(RuntimeError("boom"), run_id=MODEL)

    payload, events = _stored(repo, handler.run_id)
    assert payload["status"] == "failed"  # not left "running" forever
    assert handler.run_ids == [handler.run_id]
    assert events[str(MODEL)]["kind"] == "error"


def test_a_lone_agent_action_finalizes_its_run(tmp_path):
    repo, handler = _handler(tmp_path)
    handler.on_agent_action(_action(), run_id=CHAIN)

    payload, events = _stored(repo, handler.run_id)
    assert payload["status"] == "completed"
    assert list(events) == [f"{CHAIN}:agent_action:1"]


def test_an_agent_action_under_an_open_span_does_not_finalize_early(tmp_path):
    """The counterpart guard: marks must not cut an in-flight run short."""
    repo, handler = _handler(tmp_path)
    handler.on_chain_start({"name": "agent"}, {"q": 1}, run_id=CHAIN)
    handler.on_agent_action(_action(), run_id=CHAIN)
    assert handler.run_ids == []  # still in flight
    handler.on_chain_end({"output": "ok"}, run_id=CHAIN)

    payload, events = _stored(repo, handler.run_id)
    assert payload["status"] == "completed" and len(handler.run_ids) == 1
    assert set(events) == {str(CHAIN), f"{CHAIN}:agent_action:1"}


# -- the root-cause containment ------------------------------------------------


def test_a_refused_batch_costs_the_events_not_the_run(tmp_path, monkeypatch):
    """Any ValueError out of import_events must still leave a finalized run."""
    repo, handler = _handler(tmp_path)
    handler.on_chain_start({"name": "agent"}, {"q": 1}, run_id=CHAIN)

    real, batches = Recorder.import_events, []

    def refusing(self, events):
        batches.append(len(events))
        if len(batches) == 1:
            raise ValueError("synthetic refusal from the store")
        return real(self, events)

    monkeypatch.setattr(Recorder, "import_events", refusing)
    handler.on_chain_end({"output": "ok"}, run_id=CHAIN)

    payload, events = _stored(repo, handler.run_id)
    assert batches == [1, 1]  # the run's batch, then the loss note by itself
    assert payload["status"] == "completed"
    notes = _notes(events)
    assert len(notes) == 1 and notes[0]["read_outputs"]["dropped_events"] == 1
    assert "synthetic refusal from the store" in notes[0]["read_outputs"]["errors"][0]


def test_a_store_that_refuses_everything_still_finalizes_the_run(tmp_path, monkeypatch):
    """The floor: an empty run that says "completed" beats a stuck "running" one."""
    repo, handler = _handler(tmp_path)
    handler.on_chain_start({"name": "agent"}, {"q": 1}, run_id=CHAIN)

    def refusing(self, events):
        raise ValueError("synthetic refusal from the store")

    monkeypatch.setattr(Recorder, "import_events", refusing)
    handler.on_chain_end({"output": "ok"}, run_id=CHAIN)

    payload, events = _stored(repo, handler.run_id)
    assert payload["status"] == "completed" and payload["events"] == []
    assert events == {}


def test_a_refusal_from_finalize_is_contained(tmp_path, monkeypatch):
    repo, handler = _handler(tmp_path)
    handler.on_chain_start({"name": "agent"}, {"q": 1}, run_id=CHAIN)

    def refusing(self, status="completed"):
        raise ValueError("synthetic refusal from the store")

    monkeypatch.setattr(Recorder, "finalize", refusing)
    handler.on_chain_end({"output": "ok"}, run_id=CHAIN)  # must not raise

    assert handler.run_id is not None
    _, events = _stored(repo, handler.run_id)
    assert events[str(CHAIN)]["read_outputs"] == {"output": "ok"}


@pytest.mark.parametrize("status", ["completed", "failed", "paused"])
def test_no_live_run_is_ever_left_running(tmp_path, status):
    """Whatever a caller asks for, the run does not stay in flight after a flush."""
    repo, handler = _handler(tmp_path)
    handler.on_chain_start({"name": "agent"}, {"q": 1}, run_id=CHAIN)
    run_id = handler.flush(status)

    payload, _ = _stored(repo, run_id)
    assert payload["status"] == status
    assert handler.flush() is None
