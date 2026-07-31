"""Optional-import base class and run plumbing for the LangChain handler.

Two things live here so that :mod:`opentine.integrations.langchain` can stay a
plain, readable table of callback translations:

* the base-class shim -- ``langchain_core.callbacks.BaseCallbackHandler`` when
  the optional extra is installed, and an equivalent local stand-in when it is
  not, so importing OpenTine never requires langchain;
* the parts of the handler that are about *recording* rather than about
  LangChain: opening the run, exposing its id, and the two shapes every callback
  family shares (an error close, and an instantaneous child event).
"""

from __future__ import annotations

from typing import Any

from opentine.integrations._lc_payloads import text_value
from opentine.integrations._live_spans import DEFAULT_REF, LiveRun
from opentine.trace._import_helpers import dictionary

FRAMEWORK = "langchain"
MAX_TAGS = 64

try:  # langchain-core is an optional extra; opentine core must never need it.
    from langchain_core.callbacks.base import BaseCallbackHandler as CallbackBase
except ImportError:  # the ordinary case: no langchain in the environment

    class CallbackBase:  # type: ignore[no-redef]
        """Stand-in carrying the flags langchain-core reads off a handler.

        Only the attributes the dispatcher inspects are reproduced. Every
        callback method is defined by the subclass, so the handler behaves the
        same whether or not the real base class was importable -- which is what
        lets the whole translation be tested with no langchain installed.
        """

        raise_error = False
        run_inline = False
        ignore_llm = ignore_chain = ignore_agent = ignore_retry = False
        ignore_retriever = ignore_chat_model = ignore_custom_event = False


class HandlerBase(CallbackBase):
    """Run lifecycle shared by every LangChain-family callback."""

    def __init__(
        self,
        repo: Any,
        *,
        ref: str = DEFAULT_REF,
        prompt: str = "",
        system: str = "",
        capture: bool = False,
        raise_error: bool = False,
        **options: Any,
    ) -> None:
        # False matches langchain's own default: a fault in provenance capture
        # is logged and survived rather than killing the agent run it observes.
        # Pass raise_error=True to make a refusing repository fail loudly.
        self.raise_error = bool(raise_error)
        self.run = LiveRun(repo, ref=ref, prompt=prompt, system=system, capture=capture, **options)
        # Per-*run* state, not per-handler: a handler is normally kept for the
        # life of an application and passed to every invocation, so anything
        # keyed by callback run id has to be released when a run finalizes or it
        # grows without bound -- and, where a framework reuses run ids across
        # invocations, numbers the next run's marks as continuations of the last.
        self._marks: dict[tuple[str, str], int] = {}
        self._finalized = 0

    @property
    def run_id(self) -> str | None:
        """The run in flight, or the last one finalized; ``None`` before the first event."""
        return self.run.run_id

    @property
    def run_ids(self) -> list[str]:
        """Every run this handler has finalized, oldest first."""
        return list(self.run.run_ids)

    @property
    def events(self) -> list[Any]:
        """TraceEvents accumulated for the run currently in flight."""
        return list(self.run.events)

    def flush(self, status: str | None = None) -> str | None:
        """Finalize now, recording any still-open span as incomplete."""
        try:
            return self.run.flush(status)
        finally:
            self._reset()

    def _reset(self) -> None:
        """Drop state belonging to a run that has finalized."""
        self._marks = {}
        self._finalized = len(self.run.run_ids)

    def _attributes(
        self, event: str, tags: Any = None, metadata: Any = None, run_type: Any = None
    ) -> dict[str, Any]:
        # framework is written *after* the metadata spread, exactly as the
        # post-hoc importer does it, so run metadata cannot spoof the source.
        attributes = dict(dictionary(metadata))
        attributes["framework"] = FRAMEWORK
        attributes["langchain.event"] = event
        if run_type:
            attributes["langchain.run_type"] = str(run_type)
        if isinstance(tags, (list, tuple)) and tags:
            attributes["langchain.tags"] = [str(tag) for tag in tags[:MAX_TAGS]]
        return attributes

    def _fail(self, run_id: Any, error: Any, event: str) -> None:
        """Close a span as an error, or record one if its start was never seen."""
        self.run.mark_failed()  # before close(), which may finalize the run
        outputs = {"error": text_value(error), "error_type": type(error).__name__}
        if self.run.close(run_id, kind="error", outputs=outputs) is None:
            self.run.mark(
                run_id,
                kind="error",
                actor=event,
                outputs=outputs,
                attributes=self._attributes(event),
            )

    def _mark_child(self, run_id: Any, label: str, **fields: Any) -> None:
        """Record an instantaneous event under the span named by *run_id*."""
        key = str(run_id)
        if len(self.run.run_ids) != self._finalized:  # a run ended since the last mark
            self._reset()
        # Counted per (span, label) *within one run*: an agent that acts twice
        # gets ``:1`` and ``:2``, and the first finish stays ``agent_finish:1``
        # regardless -- including on the next invocation, which starts over.
        self._marks[key, label] = index = self._marks.get((key, label), 0) + 1
        self.run.mark(f"{key}:{label}:{index}", parent_span_id=key, **fields)
