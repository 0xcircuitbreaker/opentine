"""Live provenance capture from agent-framework callbacks.

Until now OpenTine learned about a framework run only *afterwards*, by parsing a
serialized log with :func:`opentine.trace.importers.framework_events`. That is
lossy (whatever the framework chose not to serialize is gone) and after the fact
(nothing exists until the agent has already finished). The handlers here record
the run as it happens, through the framework's own callback protocol, and
materialize it with the same :class:`~opentine.trace.schema.TraceEvent` schema
and the same :class:`~opentine.trace.recorder.Recorder` the importers use.

Optional dependencies
---------------------
Every module in this package imports cleanly with no framework installed --
``import opentine`` must never pull in langchain. Only *using* a handler against
a real framework needs the matching extra (``pip install opentine[langchain]``).
Nothing here is re-exported from the top-level ``opentine`` namespace for the
same reason; import the handler from its own module.

Supported
---------
``langchain``
    :class:`opentine.integrations.langchain.OpenTineCallbackHandler` covers
    LangChain *and* LangGraph: LangGraph is built on langchain-core and drives
    the same ``BaseCallbackHandler`` protocol, so one handler serves both.

Deferred: CrewAI
----------------
CrewAI is intentionally not implemented yet. Its surface is an event bus
(``crewai_event_bus.on(SomeEvent)``) whose payloads identify work by *object
reference* -- the emitting ``Crew``/``Agent``/``Task`` instance -- rather than by
the ``run_id``/``parent_run_id`` pair every span-shaped recorder needs, so
parentage has to be inferred from object identity and re-inferred whenever the
bus payloads change shape. Shipping that as a guess would produce plausible but
wrong causal edges, which is worse than no adapter at all. The seam is ready
when the mapping is: :class:`opentine.integrations._live_spans.LiveRun` is
framework-agnostic, and an adapter only has to turn events into ``open``/
``close``/``mark`` calls. Until then CrewAI logs remain importable post hoc via
``tine import --format crewai``.
"""

from opentine.integrations.langchain import OpenTineCallbackHandler

__all__ = ["OpenTineCallbackHandler"]
