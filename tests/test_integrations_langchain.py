"""Live LangChain/LangGraph callback capture.

The bulk of this module drives ``OpenTineCallbackHandler``'s callbacks *directly*
with the argument shapes langchain-core uses, so the translation is covered with
no optional dependency installed at all. One smoke test at the bottom is guarded
by ``pytest.importorskip("langchain_core")`` and exercises the same handler
through a real ``Runnable`` invocation.

The suite's binary-dependent-test contract in
``tests/test_release_audit_round11_misc.py`` covers modules that *shell* an
external program; this module shells nothing, so an importorskip guard is the
whole requirement here.
"""

from __future__ import annotations

import builtins
import importlib
import json
import sys
import uuid
from types import SimpleNamespace

import pytest

from opentine.integrations._lc_payloads import token_usage
from opentine.integrations.langchain import OpenTineCallbackHandler
from opentine.repository import Repo
from opentine.trace import framework_events

CHAIN, MODEL, TOOL = (uuid.UUID(int=index) for index in (1, 2, 3))


def _stored(repo: Repo, run_id: str) -> tuple[dict, dict[str, dict]]:
    """The materialized run payload plus its events, keyed by callback run id."""
    payload = repo.get(run_id).payload()
    events = []
    for oid in payload["events"]:
        event = dict(repo.get(oid).payload())
        event["oid"] = oid
        event["read_inputs"] = json.loads(repo.get(event["input_blob"]).body)
        event["read_outputs"] = json.loads(repo.get(event["output_blob"]).body)
        events.append(event)
    spans = {event["oid"]: event["span_id"] for event in events}
    for event in events:
        parents = event["parent_ids"]
        event["parent_span_id"] = spans[parents[0]] if parents else None
    return payload, {event["span_id"]: event for event in events}


def _llm_result() -> SimpleNamespace:
    message = SimpleNamespace(
        content="call the moon tool",
        tool_calls=[{"name": "moons", "args": {"planet": "mars"}}],
        usage_metadata=None,
    )
    return SimpleNamespace(
        generations=[[SimpleNamespace(text="call the moon tool", message=message)]],
        llm_output={
            "model_name": "claude-opus-5",
            "token_usage": {"prompt_tokens": 120, "completion_tokens": 45, "total_tokens": 165},
        },
    )


def _drive(handler: OpenTineCallbackHandler) -> None:
    """A nested chain -> chat model -> tool run, in langchain-core's calling order."""
    handler.on_chain_start(
        {"id": ["langchain", "schema", "runnable", "RunnableSequence"], "name": "agent"},
        {"question": "how many moons?"},
        run_id=CHAIN,
        parent_run_id=None,
        tags=["graph"],
        metadata={"langgraph_node": "planner"},
        run_type="chain",
        name="agent",
    )
    handler.on_chat_model_start(
        {"id": ["langchain", "chat_models", "ChatAnthropic"], "name": "ChatAnthropic"},
        [
            [
                SimpleNamespace(type="system", content="be terse"),
                SimpleNamespace(type="human", content="how many moons?"),
            ]
        ],
        run_id=MODEL,
        parent_run_id=CHAIN,
        tags=[],
        metadata={"ls_model_name": "claude-opus-5", "ls_provider": "anthropic"},
    )
    handler.on_llm_new_token("call", run_id=MODEL, parent_run_id=CHAIN)
    handler.on_llm_new_token(" the moon tool", run_id=MODEL, parent_run_id=CHAIN)
    handler.on_llm_end(_llm_result(), run_id=MODEL, parent_run_id=CHAIN)
    handler.on_agent_action(
        SimpleNamespace(tool="moons", tool_input={"planet": "mars"}, log="I should call moons"),
        run_id=CHAIN,
        parent_run_id=None,
    )
    handler.on_tool_start(
        {"name": "moons"},
        '{"planet": "mars"}',
        run_id=TOOL,
        parent_run_id=CHAIN,
        inputs={"planet": "mars"},
        metadata={},
    )
    handler.on_tool_end("2", run_id=TOOL, parent_run_id=CHAIN)
    handler.on_agent_finish(
        SimpleNamespace(return_values={"output": "2"}, log="done"),
        run_id=CHAIN,
        parent_run_id=None,
    )
    handler.on_chain_end({"output": "2"}, run_id=CHAIN, parent_run_id=None)


def test_a_nested_chain_model_tool_run_materializes_one_v3_run(tmp_path):
    repo = Repo.init(tmp_path)
    handler = OpenTineCallbackHandler(repo, capture=False)
    assert handler.run_id is None  # nothing is written before the first callback

    _drive(handler)

    run_id = handler.run_id
    assert run_id is not None and handler.run_ids == [run_id]
    payload, events = _stored(repo, run_id)
    assert payload["status"] == "completed"
    assert repo.read_ref("heads/main") == run_id

    chain, model, tool = events[str(CHAIN)], events[str(MODEL)], events[str(TOOL)]
    assert (chain["kind"], model["kind"], tool["kind"]) == ("model", "model", "tool")
    assert (chain["actor"], model["actor"], tool["actor"]) == ("agent", "ChatAnthropic", "moons")
    assert chain["parent_span_id"] is None
    assert model["parent_span_id"] == tool["parent_span_id"] == str(CHAIN)
    assert payload["roots"] == [chain["oid"]]
    # every span joins the root run's trace, which is the root callback run id
    assert {event["trace_id"] for event in events.values()} == {str(CHAIN)}


def test_model_step_carries_the_model_usage_and_both_payloads(tmp_path):
    repo = Repo.init(tmp_path)
    handler = OpenTineCallbackHandler(repo, capture=False)
    _drive(handler)
    _, events = _stored(repo, handler.run_id)

    model = events[str(MODEL)]
    assert model["model"] == "claude-opus-5"
    assert model["usage"] == {"input": 120, "output": 45, "total": 165}
    assert model["read_inputs"] == {
        "messages": [
            {"role": "system", "content": "be terse"},
            {"role": "human", "content": "how many moons?"},
        ]
    }
    assert model["read_outputs"] == {
        "generations": ["call the moon tool"],
        "tool_calls": [{"name": "moons", "args": {"planet": "mars"}}],
    }
    assert model["attributes"]["langchain.streamed_chunks"] == 2
    assert model["attributes"]["ls_provider"] == "anthropic"
    assert model["duration"] >= 0 and model["time_unix"] > 0

    tool = events[str(TOOL)]
    assert tool["read_inputs"] == {"planet": "mars"}
    assert tool["read_outputs"] == {"output": "2"}
    chain = events[str(CHAIN)]
    assert chain["read_inputs"] == {"question": "how many moons?"}
    assert chain["read_outputs"] == {"output": "2"}
    assert chain["attributes"]["langchain.run_type"] == "chain"
    assert chain["attributes"]["langchain.tags"] == ["graph"]


def test_run_metadata_cannot_spoof_the_recorded_framework(tmp_path):
    repo = Repo.init(tmp_path)
    handler = OpenTineCallbackHandler(repo, capture=False)
    handler.on_chain_start({}, {}, run_id=CHAIN, metadata={"framework": "spoofed", "kept": True})
    handler.on_chain_end({}, run_id=CHAIN)
    _, events = _stored(repo, handler.run_id)

    attributes = events[str(CHAIN)]["attributes"]
    assert attributes["framework"] == "langchain" and attributes["kept"] is True


def test_agent_action_and_finish_become_children_of_the_agent_span(tmp_path):
    repo = Repo.init(tmp_path)
    handler = OpenTineCallbackHandler(repo, capture=False)
    _drive(handler)
    _, events = _stored(repo, handler.run_id)

    action = events[f"{CHAIN}:agent_action:1"]
    finish = events[f"{CHAIN}:agent_finish:1"]
    assert action["parent_span_id"] == finish["parent_span_id"] == str(CHAIN)
    assert action["actor"] == "agent_action" and finish["actor"] == "agent_finish"
    assert action["read_outputs"] == {
        "tool": "moons",
        "tool_input": {"planet": "mars"},
        "log": "I should call moons",
    }
    assert finish["read_outputs"] == {"return_values": {"output": "2"}, "log": "done"}


def test_the_live_events_agree_with_the_post_hoc_framework_importer(tmp_path):
    """The same run, serialized and re-imported, must describe the same graph."""
    repo = Repo.init(tmp_path)
    handler = OpenTineCallbackHandler(repo, capture=False)
    _drive(handler)
    payload, events = _stored(repo, handler.run_id)

    ordered = [events[span] for span in (str(CHAIN), str(MODEL), str(TOOL))]
    records = [
        {
            "run_id": event["span_id"],
            "parent_run_id": event["parent_span_id"],
            "trace_id": event["trace_id"],
            "name": event["actor"],
            "type": event["kind"],
            "model": event["model"],
            "timestamp": event["time_unix"],
            "duration": event["duration"],
            "inputs": event["read_inputs"],
            "outputs": event["read_outputs"],
            "usage": event["usage"],
        }
        for event in ordered
    ]
    imported = framework_events(records, "langchain")

    assert len(imported) == len(ordered)
    for live, post_hoc in zip(ordered, imported, strict=True):
        assert post_hoc.span_id == live["span_id"]  # run_id -> span
        assert post_hoc.parent_span_id == live["parent_span_id"]  # parent_run_id -> parent
        assert post_hoc.trace_id == live["trace_id"]
        assert post_hoc.actor == live["actor"]  # name -> actor
        assert post_hoc.kind == live["kind"]
        assert post_hoc.model == live["model"]
        assert post_hoc.timestamp == live["time_unix"]
        assert post_hoc.duration == live["duration"]
        assert post_hoc.inputs == live["read_inputs"]
        assert post_hoc.outputs == live["read_outputs"]
        assert post_hoc.usage == live["usage"]
        assert post_hoc.attributes["framework"] == live["attributes"]["framework"]


@pytest.mark.parametrize(
    "raw,expected",
    [
        # OpenAI shape, as langchain reports it in llm_output["token_usage"]
        (
            {"prompt_tokens": 7, "completion_tokens": 3, "total_tokens": 10},
            {"input": 7, "output": 3, "total": 10},
        ),
        # Anthropic shape, as langchain reports it in llm_output["usage"]
        (
            {
                "input_tokens": 7,
                "output_tokens": 3,
                "cache_read_input_tokens": 4,
                "cache_creation_input_tokens": 2,
            },
            {"input": 7, "output": 3, "cache_read": 4, "cache_write_5m": 2},
        ),
        # langchain's normalized usage_metadata, including its nested details
        (
            {
                "input_tokens": 7,
                "output_tokens": 3,
                "total_tokens": 10,
                "input_token_details": {"cache_read": 4},
                "output_token_details": {"reasoning": 1},
            },
            {"input": 7, "output": 3, "total": 10, "cache_read": 4, "reasoning": 1},
        ),
        # nothing usable is not an error, it is simply no usage
        ({"prompt_tokens": "7", "completion_tokens": -1}, {}),
        (None, {}),
    ],
)
def test_provider_usage_shapes_map_onto_opentine_dimensions(raw, expected):
    assert token_usage(raw) == expected


def test_a_tool_error_records_an_error_step_and_fails_the_run(tmp_path):
    repo = Repo.init(tmp_path)
    handler = OpenTineCallbackHandler(repo, capture=False)
    handler.on_chain_start({"name": "agent"}, {"q": 1}, run_id=CHAIN)
    handler.on_tool_start({"name": "moons"}, "{}", run_id=TOOL, parent_run_id=CHAIN)
    handler.on_tool_error(RuntimeError("no such planet"), run_id=TOOL, parent_run_id=CHAIN)
    handler.on_chain_end({"output": None}, run_id=CHAIN)

    payload, events = _stored(repo, handler.run_id)
    assert payload["status"] == "failed"
    failed = events[str(TOOL)]
    assert failed["kind"] == "error" and failed["parent_span_id"] == str(CHAIN)
    assert failed["read_outputs"] == {"error": "no such planet", "error_type": "RuntimeError"}


def test_an_error_whose_start_was_never_seen_is_still_recorded(tmp_path):
    repo = Repo.init(tmp_path)
    handler = OpenTineCallbackHandler(repo, capture=False)
    handler.on_chain_start({"name": "agent"}, {}, run_id=CHAIN)
    handler.on_llm_error(ValueError("boom"), run_id=MODEL, parent_run_id=CHAIN)
    handler.on_chain_end({}, run_id=CHAIN)

    payload, events = _stored(repo, handler.run_id)
    assert payload["status"] == "failed"
    assert events[str(MODEL)]["kind"] == "error"


def test_each_invocation_finalizes_its_own_run(tmp_path):
    repo = Repo.init(tmp_path)
    handler = OpenTineCallbackHandler(repo, capture=False)
    for index in (10, 11):
        run = uuid.UUID(int=index)
        handler.on_chain_start({"name": "agent"}, {"n": index}, run_id=run)
        handler.on_chain_end({"n": index}, run_id=run)

    assert len(handler.run_ids) == 2 and len(set(handler.run_ids)) == 2
    assert repo.read_ref("heads/main") == handler.run_ids[-1]
    for index, run_id in zip((10, 11), handler.run_ids, strict=True):
        _, events = _stored(repo, run_id)
        assert list(events) == [str(uuid.UUID(int=index))]


def test_flush_records_a_still_open_span_as_incomplete(tmp_path):
    repo = Repo.init(tmp_path)
    handler = OpenTineCallbackHandler(repo, capture=False)
    handler.on_chain_start({"name": "agent"}, {"q": 1}, run_id=CHAIN)

    run_id = handler.flush("paused")
    payload, events = _stored(repo, run_id)
    assert payload["status"] == "paused"
    assert events[str(CHAIN)]["attributes"]["opentine.incomplete"] is True
    assert handler.flush() is None  # nothing left to materialize


def test_an_unstorable_payload_is_confined_to_its_own_field(tmp_path):
    """A value the blob gate refuses must not cost the whole completed run."""
    repo = Repo.init(tmp_path)
    handler = OpenTineCallbackHandler(repo, capture=False)
    handler.on_chain_start({"name": "agent"}, {"q": 1}, run_id=CHAIN)
    handler.on_tool_start({"name": "moons"}, "{}", run_id=TOOL, parent_run_id=CHAIN)
    handler.on_tool_end("\ud800unpaired surrogate", run_id=TOOL, parent_run_id=CHAIN)
    handler.on_chain_end({"output": "ok"}, run_id=CHAIN)

    _, events = _stored(repo, handler.run_id)
    assert "opentine.unstorable" in events[str(TOOL)]["read_outputs"]
    assert events[str(TOOL)]["read_inputs"] == {"input": "{}"}
    assert events[str(CHAIN)]["read_outputs"] == {"output": "ok"}


def test_capture_loss_is_reported_in_band(tmp_path):
    repo = Repo.init(tmp_path)
    handler = OpenTineCallbackHandler(repo, capture=False, max_events=1)
    handler.on_chain_start({"name": "agent"}, {"q": 1}, run_id=CHAIN)
    handler.on_tool_start({"name": "moons"}, "{}", run_id=TOOL, parent_run_id=CHAIN)
    handler.on_tool_end("2", run_id=TOOL, parent_run_id=CHAIN)
    handler.on_chain_end({"output": "2"}, run_id=CHAIN)

    _, events = _stored(repo, handler.run_id)
    notes = [event for event in events.values() if event["actor"] == "opentine.capture"]
    assert len(notes) == 1 and notes[0]["kind"] == "error"
    assert notes[0]["read_outputs"]["dropped_events"] == 1


def test_retriever_spans_are_recorded_as_tool_steps(tmp_path):
    repo = Repo.init(tmp_path)
    handler = OpenTineCallbackHandler(repo, capture=False)
    handler.on_retriever_start({"name": "faiss"}, "moons of mars", run_id=TOOL)
    handler.on_retriever_end(
        [SimpleNamespace(page_content="Phobos and Deimos", metadata={"source": "wiki"})],
        run_id=TOOL,
    )

    _, events = _stored(repo, handler.run_id)
    retriever = events[str(TOOL)]
    assert retriever["kind"] == "tool" and retriever["actor"] == "faiss"
    assert retriever["read_inputs"] == {"query": "moons of mars"}
    assert retriever["read_outputs"] == {
        "documents": [{"page_content": "Phobos and Deimos", "metadata": {"source": "wiki"}}]
    }


def test_the_handler_module_imports_with_langchain_core_absent(monkeypatch):
    """CI installs every extra, so absence has to be simulated rather than assumed."""
    real_import = builtins.__import__

    def blocked(name, *args, **kwargs):
        if name == "langchain_core" or name.startswith("langchain_core."):
            raise ImportError("langchain_core is not installed")
        return real_import(name, *args, **kwargs)

    for name in [name for name in sys.modules if name.startswith("opentine.integrations")]:
        monkeypatch.delitem(sys.modules, name)
    monkeypatch.delitem(sys.modules, "langchain_core", raising=False)
    monkeypatch.setattr(builtins, "__import__", blocked)

    base = importlib.import_module("opentine.integrations._lc_base")
    module = importlib.import_module("opentine.integrations.langchain")
    assert base.CallbackBase.__module__ == "opentine.integrations._lc_base"
    assert base.CallbackBase.raise_error is False and base.CallbackBase.ignore_llm is False
    assert issubclass(module.OpenTineCallbackHandler, base.CallbackBase)


def test_a_real_langchain_core_invocation_records_the_same_shape(tmp_path):
    """Smoke test against the genuine article; skipped where the extra is absent."""
    pytest.importorskip("langchain_core")
    from langchain_core.callbacks.base import BaseCallbackHandler
    from langchain_core.language_models.fake_chat_models import FakeListChatModel
    from langchain_core.runnables import RunnableLambda
    from langchain_core.tools import tool

    assert issubclass(OpenTineCallbackHandler, BaseCallbackHandler)

    @tool
    def moons(planet: str) -> str:
        """Count the moons of a planet."""
        return "2"

    chat = FakeListChatModel(responses=["call the moon tool"])

    def plan(question: str, config) -> str:
        chat.invoke(question, config=config)
        return moons.invoke({"planet": "mars"}, config=config)

    repo = Repo.init(tmp_path)
    handler = OpenTineCallbackHandler(repo, capture=False)
    result = RunnableLambda(plan).invoke("how many moons?", config={"callbacks": [handler]})

    assert result == "2"
    payload, events = _stored(repo, handler.run_id)
    assert payload["status"] == "completed"
    kinds = [event["kind"] for event in events.values()]
    assert kinds.count("tool") == 1 and kinds.count("model") >= 2
    assert "moons" in {event["actor"] for event in events.values()}
    assert len({event["trace_id"] for event in events.values()}) == 1
    roots = [event for event in events.values() if event["parent_span_id"] is None]
    assert len(roots) == 1 and payload["roots"] == [roots[0]["oid"]]
