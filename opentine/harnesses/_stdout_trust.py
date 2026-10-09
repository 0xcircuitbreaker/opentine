"""Whose words a harness's stdout is: the CLI's events, or the agent's prose.

A text-mode agent CLI (``gemini -p``, ``grok exec``, ``codex exec``) prints the
model's answer, so every line of it is model-authored. Every parser still read
a JSON-shaped line there as a structured event and a "cost: $250" as a charge,
so an answer could forge ``deploy_prod`` tool steps, errors, and money in the
record -- and trip a cost budget (audit 0.9.1, D-6).

Two switches decide it, per harness:

* ``structured_stdout`` -- whether a JSON line is an event. ``None`` (the
  default) infers it from the command: a JSON output flag (``--json``,
  ``--output-format stream-json``, ``--format=json``) means the CLI encodes the
  model's text *inside* its events, where it cannot start a line of its own.
* ``meter_free_text`` -- whether a currency amount in free text is booked.
  Only for a command the operator wrote (``generic``, ``pi``), which may report
  its own cost in prose; for a vendor CLI, free text is the model's.
"""

from __future__ import annotations

from typing import Any

from opentine.harnesses._types import cost_from_text, parse_json_event

_JSON_FORMATS = frozenset({"json", "jsonl", "stream-json", "stream_json", "ndjson"})


def _json_flag(command: tuple[str, ...]) -> bool:
    for token in command:
        lowered = token.lower()
        if lowered == "--json" or lowered in _JSON_FORMATS:
            return True
        if "=" in lowered and lowered.split("=", 1)[1] in _JSON_FORMATS:
            return True
    return False


class StdoutTrust:
    structured_stdout: bool | None = None
    meter_free_text: bool = False
    command: tuple[str, ...]

    def _stdout_is_structured(self) -> bool:
        if self.structured_stdout is not None:
            return self.structured_stdout
        return _json_flag(tuple(self.command) + tuple(getattr(self, "extra_args", ())))

    def json_event(self, line: str) -> dict[str, Any] | None:
        return parse_json_event(line) if self._stdout_is_structured() else None

    def text_cost(self, line: str) -> float:
        return cost_from_text(line) if self.meter_free_text else 0.0
