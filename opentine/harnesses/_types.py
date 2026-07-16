"""Normalized harness records and parsing helpers."""

from __future__ import annotations

import json
import math
import re
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol

from opentine.core import StepKind, step_id


def _meter(value: Any, name: str) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError(f"harness {name} must be finite and non-negative") from exc
    if isinstance(value, bool) or not math.isfinite(number) or number < 0:
        raise ValueError(f"harness {name} must be finite and non-negative")
    return number


def meter_value(data: Mapping[str, Any], *names: str) -> Any:
    """Return the first present, non-null external metric, or zero."""
    for name in names:
        value = data.get(name)
        if value is not None:
            return value
    return 0.0


def _jsonable(value: Any) -> Any:
    if value is None or isinstance(value, str | int | float | bool):
        return value
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        return [_jsonable(item) for item in value]
    if isinstance(value, bytes | bytearray):
        return value.decode(errors="replace")
    return repr(value)


def _coerce_kind(kind: StepKind | str) -> StepKind:
    if isinstance(kind, StepKind):
        return kind
    try:
        return StepKind(kind)
    except ValueError:
        return StepKind.think


def _short_id(prefix: str, payload: Mapping[str, Any]) -> str:
    return step_id(StepKind.model, {"prefix": prefix, **_jsonable(payload)})


@dataclass(slots=True)
class HarnessStep:
    kind: StepKind | str
    inputs: dict[str, Any] = field(default_factory=dict)
    outputs: dict[str, Any] = field(default_factory=dict)
    parent_id: str | None = None
    model_info: str | None = None
    cost: float = 0.0
    duration: float = 0.0

    def __post_init__(self) -> None:
        self.cost = _meter(self.cost, "cost")
        self.duration = _meter(self.duration, "duration")

    @classmethod
    def from_line(
        cls,
        line: str,
        *,
        kind: StepKind = StepKind.think,
        model_info: str | None = None,
    ) -> HarnessStep:
        return cls(kind=kind, inputs={"text": line}, model_info=model_info)


StepCallback = Callable[[HarnessStep], str]


class HarnessAdapter(Protocol):
    @property
    def name(self) -> str: ...
    @property
    def model_info(self) -> str: ...
    @property
    def supports_resume(self) -> bool: ...

    def execute(
        self,
        task: str,
        context: dict[str, Any] | None = None,
        step_callback: StepCallback | None = None,
    ) -> Any | Awaitable[Any]: ...


def parse_json_event(line: str) -> dict[str, Any] | None:
    stripped = line.strip()
    if not stripped.startswith("{"):
        return None
    try:
        data = json.loads(stripped)
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def cost_from_text(text: str) -> float:
    match = re.search(r"(?:cost|price)\s*[=:]\s*\$?([0-9]+(?:\.[0-9]+)?)", text, re.I)
    return float(match.group(1)) if match else 0.0
