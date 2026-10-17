"""Whose words a harness's stdout is: the CLI's events, or the agent's prose.

A text-mode agent CLI (``gemini -p``, ``grok exec``, ``codex exec``) prints the
model's answer, so every line of it is model-authored. Every parser still read
a JSON-shaped line there as a structured event and a "cost: $250" as a charge,
so an answer could forge ``deploy_prod`` tool steps, errors, and money in the
record -- and trip a cost budget (audit 0.9.1, D-6).

Two switches decide it, per harness:

* ``structured_stdout`` -- whether a JSON line is an event. ``None`` (the
  default) infers it from the command: the last output-format option
  (``--json``, ``--output-format stream-json``, ``--format=json``; see
  :attr:`StdoutTrust.json_options`) asking for JSON means the CLI encodes the
  model's text *inside* its events, where it cannot start a line of its own.
* ``meter_free_text`` -- whether a currency amount in free text is booked.
  Only for a command the operator wrote (``generic``, ``pi``), which may report
  its own cost in prose; for a vendor CLI, free text is the model's.
"""

from __future__ import annotations

from typing import Any

from opentine.harnesses._types import cost_from_text, parse_json_event

#: Options whose value names the CLI's output format, and the values that mean
#: "events, not prose". ``--json`` alone is a switch. A subclass whose CLI spells
#: it differently overrides :attr:`StdoutTrust.json_options` / ``json_values``.
JSON_OPTIONS = ("--output-format", "--format", "-o", "--output", "--mode", "--json")
JSON_VALUES = ("json", "stream-json", "jsonl", "ndjson")


def _json_flag(
    command: tuple[str, ...],
    options: tuple[str, ...] = JSON_OPTIONS,
    values: tuple[str, ...] = JSON_VALUES,
) -> bool:
    """Whether the LAST output-format option on *command* asks for JSON.

    Only a listed option counts: a bare ``json`` word, or ``--log-format=json``,
    says nothing about stdout. A later ``--output-format text`` overrides an
    earlier ``stream-json``, as the CLI itself would read it.
    """
    wanted = {value.lower() for value in values}
    switches = {option for option in options if option == "--json"}
    valued = {option for option in options if option != "--json"}
    structured = False
    index = 0
    while index < len(command):
        token = command[index]
        name, has_value, inline = token.partition("=")
        if token in switches:
            structured = True
        elif has_value and name in switches:
            structured = inline.lower() not in {"false", "0", "no"}
        elif has_value and name in valued:
            structured = inline.lower() in wanted
        elif token in valued and index + 1 < len(command):
            index += 1
            structured = command[index].lower() in wanted
        index += 1
    return structured


class StdoutTrust:
    structured_stdout: bool | None = None
    meter_free_text: bool = False
    json_options: tuple[str, ...] = JSON_OPTIONS
    json_values: tuple[str, ...] = JSON_VALUES
    command: tuple[str, ...]

    def _stdout_is_structured(self) -> bool:
        if self.structured_stdout is not None:
            return self.structured_stdout
        command = tuple(self.command) + tuple(getattr(self, "extra_args", ()))
        return _json_flag(command, self.json_options, self.json_values)

    def json_event(self, line: str) -> dict[str, Any] | None:
        return parse_json_event(line) if self._stdout_is_structured() else None

    def text_cost(self, line: str) -> float:
        return cost_from_text(line) if self.meter_free_text else 0.0
