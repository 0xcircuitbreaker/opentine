"""A process harness driven by a dialect: the CLI's JSON events -> steps.

The harness owns the process (spawn, containment, limits) and the trust rule
(a JSON line is an event only when the command asked for JSON output, decided by
the LAST output-format option, see ``_stdout_trust``). The dialect owns the
event schema. Unknown event types fall back to the generic JSON parser of
:class:`JSONOrTextHarness`; event types a dialect knows to be noise (partial
deltas, heartbeats) are consumed silently.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from opentine.core import StepKind
from opentine.harnesses._dialect_base import flag_value, provider_name, split_model
from opentine.harnesses._types import HarnessStep, loads_event
from opentine.harnesses.agent_cli import JSONOrTextHarness

#: A pretty-printed JSON document (``--json`` envelopes) is at most this many lines.
MAX_DOCUMENT_LINES = 10_000


class Dialect:
    """Per-run state for one CLI's event schema. Subclasses implement :meth:`step`."""

    cli = "cli"
    #: Provider recorded when neither the events nor the command name one.
    default_provider = ""
    model_flags: tuple[str, ...] = ("-m", "--model")
    provider_flags: tuple[str, ...] = ("--provider",)

    def __init__(self, command: Sequence[str] = (), env: Mapping[str, str] | None = None):
        self.command = tuple(command)
        self.env = dict(env or {})
        flagged_provider = provider_name(flag_value(self.command, *self.provider_flags))
        self.model, self.provider = split_model(
            flag_value(self.command, *self.model_flags), flagged_provider
        )
        self.provider = self.provider or self.default_provider

    def set_model(self, raw: Any, provider: Any = None) -> None:
        model, named = split_model(raw, provider_name(provider))
        if model:
            self.model = model
        if named:
            self.provider = named

    def step(self, data: dict[str, Any]) -> list[HarnessStep] | None:
        """Steps for one event; ``[]`` consumes it, ``None`` defers to the generic parser."""
        raise NotImplementedError


class DialectHarness(JSONOrTextHarness):
    """A JSON-or-text CLI harness whose JSON events a :class:`Dialect` reads."""

    dialect: type[Dialect] = Dialect
    #: The option a prompt is passed through (``-p``), when it is the command's last
    #: token: ``--harness-arg`` values go before it, not between it and the task.
    prompt_flag: str | None = None
    #: Join a pretty-printed JSON document (``--json`` envelopes) back into one event.
    multiline_json = False
    #: What a run records: model / usage / cost / tools -- shown by ``tine harnesses``.
    fidelity: Mapping[str, bool] = {}
    invocation_kind = StepKind.think
    #: Bare switches that select JSON output (Amp's ``--stream-json``).
    json_switches: tuple[str, ...] = ()

    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self._state: Dialect | None = None
        self._document: list[str] = []

    @property
    def state(self) -> Dialect:
        if self._state is None:
            self._state = self.dialect(self.command + self.extra_args, self.build_env())
        return self._state

    @property
    def model_info(self) -> str:
        return (self._state.model if self._state else "") or self.name

    def _stdout_is_structured(self) -> bool:
        if self.structured_stdout is None and self.json_switches:
            command = (*self.command, *self.extra_args)
            if any(token in self.json_switches for token in command):
                return True
        return super()._stdout_is_structured()

    def build_command(self, task: str, context: dict[str, Any] | None = None) -> list[str]:
        command = super().build_command(task, context)
        flag = self.prompt_flag
        if flag and self.extra_args and self.command and self.command[-1] == flag:
            # [*command, *extra, task] -> [*command[:-1], *extra, flag, task]
            command = [*self.command[:-1], *self.extra_args, flag, task]
        self._state = self.dialect(tuple(command[:-1]), self.build_env())
        self._document = []
        return command

    def parse_line(self, line: str) -> HarnessStep | list[HarnessStep] | None:
        if not line:
            return None
        if self.multiline_json and self._stdout_is_structured():
            joined = self._join_document(line)
            if joined is None:
                return None
            if isinstance(joined, HarnessStep):
                return joined
            if isinstance(joined, dict):
                return self._event(joined)
        data = self.json_event(line)
        if data:
            return self._event(data)
        return self._parse_text_line(line)

    def _event(self, data: dict[str, Any]) -> HarnessStep | list[HarnessStep] | None:
        steps = self.state.step(data)
        if steps is None:
            return self._parse_json_event(data)
        return steps or None

    def _join_document(self, line: str) -> dict[str, Any] | HarnessStep | bool | None:
        """``None`` while buffering, the event when complete, ``False`` to parse the line.

        A document that fails to parse is recorded as an error step, never dropped
        silently with only its closing brace left as text (final pass, #10).
        """
        if not self._document and line.rstrip() != "{":
            return False
        self._document.append(line)
        # Only the unindented brace closes the document: nested ones are indented.
        if line.rstrip() != "}" and len(self._document) < MAX_DOCUMENT_LINES:
            return None
        text, self._document = "\n".join(self._document), []
        try:
            data = loads_event(text)
        except (ValueError, RecursionError):
            data = None
        if isinstance(data, dict):
            return data
        return HarnessStep(
            kind=StepKind.error,
            inputs={"error": f"unparseable {self.name} JSON document", "text": text[-4000:]},
            model_info=self.model_info,
        )


__all__ = ["Dialect", "DialectHarness"]
