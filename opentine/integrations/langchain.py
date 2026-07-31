"""Live OpenTine provenance for LangChain *and* LangGraph.

LangGraph is built on langchain-core and dispatches the same callback protocol,
so a single ``BaseCallbackHandler`` implementation covers both: pass the handler
in ``config={"callbacks": [handler]}`` (or to ``RunnableConfig``/``.invoke``) and
every chain, graph node, chat model, tool and retriever underneath it is recorded
as it runs, instead of being reconstructed afterwards from a serialized log::

    from opentine.integrations.langchain import OpenTineCallbackHandler
    from opentine.repository import Repo

    handler = OpenTineCallbackHandler(Repo.init("runs"))
    graph.invoke({"question": "..."}, config={"callbacks": [handler]})
    run_id = handler.run_id

The mapping is deliberately the one :func:`opentine.trace.importers.
framework_events` already applies post hoc, so a live run and an imported run of
the same agent describe the same graph:

==========================  =============================================
callback argument           :class:`~opentine.trace.schema.TraceEvent`
==========================  =============================================
``run_id``                  ``span_id``
``parent_run_id``           ``parent_span_id`` (root run id -> ``trace_id``)
``name`` / ``serialized``   ``actor``
chain / llm / chat model    ``kind="model"``
tool / retriever            ``kind="tool"``
any ``on_*_error``          ``kind="error"``
start -> end wall clock     ``timestamp`` + ``duration``
``LLMResult`` token usage   ``usage`` (canonical OpenTine dimensions)
``metadata``                ``attributes`` (``framework`` is written last)
==========================  =============================================

Importing this module never requires langchain: the base class falls back to a
local stand-in (:mod:`opentine.integrations._lc_base`) when ``langchain_core`` is
absent, and every payload is read duck-typed in
:mod:`opentine.integrations._lc_payloads`.
"""

from __future__ import annotations

from typing import Any

from opentine.integrations._lc_base import HandlerBase
from opentine.integrations._lc_payloads import (
    attribute,
    document_payloads,
    llm_result,
    message_rows,
    model_name,
    run_name,
    text_value,
)
from opentine.trace._import_helpers import mapping

MAX_PROMPTS = 64


class OpenTineCallbackHandler(HandlerBase):
    """Record a LangChain/LangGraph invocation into a v3 repository as it happens.

    The run is created at the first callback and finalized when the last open
    span closes, so one ``.invoke()`` is one run; :attr:`run_id` names it and
    :attr:`run_ids` collects every run this handler has finalized.
    """

    # -- chains and graph nodes ------------------------------------------------

    def on_chain_start(
        self,
        serialized: Any,
        inputs: Any,
        *,
        run_id: Any,
        parent_run_id: Any = None,
        tags: Any = None,
        metadata: Any = None,
        run_type: Any = None,
        name: Any = None,
        **kwargs: Any,
    ) -> None:
        self.run.open(
            run_id,
            parent_run_id,
            kind="model",
            actor=run_name(serialized, name, kwargs, "chain"),
            inputs=mapping(inputs),
            attributes=self._attributes("chain", tags, metadata, run_type),
        )

    def on_chain_end(self, outputs: Any, *, run_id: Any, **kwargs: Any) -> None:
        self.run.close(run_id, outputs=mapping(outputs))

    def on_chain_error(self, error: Any, *, run_id: Any, **kwargs: Any) -> None:
        self._fail(run_id, error, "chain")

    # -- models ----------------------------------------------------------------

    def on_llm_start(
        self,
        serialized: Any,
        prompts: Any,
        *,
        run_id: Any,
        parent_run_id: Any = None,
        tags: Any = None,
        metadata: Any = None,
        name: Any = None,
        **kwargs: Any,
    ) -> None:
        listed = list(prompts)[:MAX_PROMPTS] if isinstance(prompts, (list, tuple)) else []
        self.run.open(
            run_id,
            parent_run_id,
            kind="model",
            actor=run_name(serialized, name, kwargs, "llm"),
            model=model_name(serialized, metadata, kwargs),
            inputs={"prompts": [text_value(prompt) for prompt in listed]},
            attributes=self._attributes("llm", tags, metadata),
        )

    def on_chat_model_start(
        self,
        serialized: Any,
        messages: Any,
        *,
        run_id: Any,
        parent_run_id: Any = None,
        tags: Any = None,
        metadata: Any = None,
        name: Any = None,
        **kwargs: Any,
    ) -> None:
        self.run.open(
            run_id,
            parent_run_id,
            kind="model",
            actor=run_name(serialized, name, kwargs, "chat_model"),
            model=model_name(serialized, metadata, kwargs),
            inputs={"messages": message_rows(messages)},
            attributes=self._attributes("chat_model", tags, metadata),
        )

    def on_llm_new_token(self, token: Any, *, run_id: Any, **kwargs: Any) -> None:
        span = self.run.update(run_id)
        if span is not None:
            seen = span.attributes.get("langchain.streamed_chunks")
            span.attributes["langchain.streamed_chunks"] = (seen if type(seen) is int else 0) + 1

    def on_llm_end(self, response: Any, *, run_id: Any, **kwargs: Any) -> None:
        outputs, usage, model = llm_result(response)
        # model stays whatever on_*_start recorded unless the result names one.
        self.run.close(run_id, outputs=outputs, usage=usage, model=model or None)

    def on_llm_error(self, error: Any, *, run_id: Any, **kwargs: Any) -> None:
        self._fail(run_id, error, "llm")

    # -- tools and retrievers --------------------------------------------------

    def on_tool_start(
        self,
        serialized: Any,
        input_str: Any,
        *,
        run_id: Any,
        parent_run_id: Any = None,
        tags: Any = None,
        metadata: Any = None,
        inputs: Any = None,
        name: Any = None,
        **kwargs: Any,
    ) -> None:
        self.run.open(
            run_id,
            parent_run_id,
            kind="tool",
            actor=run_name(serialized, name, kwargs, "tool"),
            inputs=mapping(inputs) if inputs is not None else {"input": text_value(input_str)},
            attributes=self._attributes("tool", tags, metadata),
        )

    def on_tool_end(self, output: Any, *, run_id: Any, **kwargs: Any) -> None:
        self.run.close(run_id, outputs={"output": text_value(output)})

    def on_tool_error(self, error: Any, *, run_id: Any, **kwargs: Any) -> None:
        self._fail(run_id, error, "tool")

    def on_retriever_start(
        self,
        serialized: Any,
        query: Any,
        *,
        run_id: Any,
        parent_run_id: Any = None,
        tags: Any = None,
        metadata: Any = None,
        name: Any = None,
        **kwargs: Any,
    ) -> None:
        self.run.open(
            run_id,
            parent_run_id,
            kind="tool",
            actor=run_name(serialized, name, kwargs, "retriever"),
            inputs={"query": text_value(query)},
            attributes=self._attributes("retriever", tags, metadata),
        )

    def on_retriever_end(self, documents: Any, *, run_id: Any, **kwargs: Any) -> None:
        self.run.close(run_id, outputs={"documents": document_payloads(documents)})

    def on_retriever_error(self, error: Any, *, run_id: Any, **kwargs: Any) -> None:
        self._fail(run_id, error, "retriever")

    # -- agent decisions -------------------------------------------------------
    # These carry the *enclosing* run's id rather than one of their own, so they
    # are recorded as instantaneous children of that span instead of as a pair.

    def on_agent_action(self, action: Any, *, run_id: Any, **kwargs: Any) -> None:
        self._mark_child(
            run_id,
            "agent_action",
            kind="model",
            actor="agent_action",
            outputs={
                "tool": text_value(attribute(action, "tool")),
                "tool_input": text_value(attribute(action, "tool_input")),
                "log": text_value(attribute(action, "log")),
            },
            attributes=self._attributes("agent_action"),
        )

    def on_agent_finish(self, finish: Any, *, run_id: Any, **kwargs: Any) -> None:
        self._mark_child(
            run_id,
            "agent_finish",
            kind="model",
            actor="agent_finish",
            outputs={
                "return_values": mapping(attribute(finish, "return_values")),
                "log": text_value(attribute(finish, "log")),
            },
            attributes=self._attributes("agent_finish"),
        )
