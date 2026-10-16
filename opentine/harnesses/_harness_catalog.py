"""Harness classes built from the catalogue rows (``_harness_rows``)."""

from __future__ import annotations

from typing import Any

from opentine.harnesses._dialect_harness import DialectHarness
from opentine.harnesses._harness_rows import FIDELITY, ROWS, Row
from opentine.harnesses.agent_cli import JSONOrTextHarness

#: Class names that predate the catalog keep their spelling.
_NAMES = {
    "gemini": "GeminiCLIHarness",
    "grok": "GrokBuildHarness",
    "opencode": "OpenCodeHarness",
    "openclaw": "OpenClawHarness",
    "openhands": "OpenHandsHarness",
}


def _class_name(name: str) -> str:
    if name in _NAMES:
        return _NAMES[name]
    return "".join(part.title() for part in name.split("-")) + "Harness"


def harness_class(row: Row) -> type[JSONOrTextHarness]:
    """Build the harness class for one row."""
    attrs: dict[str, Any] = {
        "__doc__": row.doc,
        "__module__": __name__,
        "name": row.name,
        "default_command": row.command,
        "login_env_keys": row.login_env_keys,
        "fidelity": dict(zip(FIDELITY, row.fidelity, strict=True)),
        "prompt_flag": row.prompt_flag,
        **row.extra,
    }
    if row.json_options is not None:
        attrs["json_options"] = row.json_options
    if row.json_values is not None:
        attrs["json_values"] = row.json_values
    if row.dialect is None:
        attrs["model_info"] = property(lambda self, _label=row.name: _label)
        return type(_class_name(row.name), (_PromptFlagHarness,), attrs)
    attrs.update(dialect=row.dialect, multiline_json=row.multiline_json)
    return type(_class_name(row.name), (DialectHarness,), attrs)


class _PromptFlagHarness(JSONOrTextHarness):
    """A schema-less preset that still keeps ``--harness-arg`` before its prompt flag."""

    prompt_flag: str | None = None

    def build_command(self, task: str, context: dict[str, Any] | None = None) -> list[str]:
        command = super().build_command(task, context)
        flag = self.prompt_flag
        if flag and self.extra_args and self.command and self.command[-1] == flag:
            command = [*self.command[:-1], *self.extra_args, flag, task]
        return command


HARNESS_CLASSES: dict[str, type[JSONOrTextHarness]] = {row.name: harness_class(row) for row in ROWS}

__all__ = ["FIDELITY", "HARNESS_CLASSES", "ROWS", "Row", "harness_class"]
