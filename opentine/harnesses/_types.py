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


def _numeric(value: Any) -> float:
    """Coerce a harness-reported metric to a number, or 0.0 if it is not one."""
    if isinstance(value, bool):
        return 0.0
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0.0
    return number if math.isfinite(number) and number >= 0 else 0.0


def duration_seconds(data: Mapping[str, Any]) -> Any:
    """Read a harness-reported duration as seconds, converting ``*_ms`` fields.

    ``Step.duration`` is seconds — it is rendered as ``…s`` and compared against
    ``Budget.max_duration``. Storing a millisecond field verbatim inflates every
    reported duration 1000x and can abort a run on a duration budget it never
    actually exceeded.
    """
    seconds = _numeric(meter_value(data, "duration", "duration_s", "duration_seconds"))
    if seconds:
        return seconds
    millis = _numeric(meter_value(data, "duration_ms", "duration_millis", "latency_ms"))
    # Coerce before deciding, not after. Harnesses emit JSON numbers as strings
    # ({"duration_ms": "1500"}), and a type check that ran first passed those
    # through unconverted — keeping the whole 1000x inflation the conversion
    # exists to remove, which can abort a run on a duration budget it never hit.
    return millis / 1000.0 if millis else 0.0


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
    """Scrape a charge out of a harness's free-text output.

    A currency marker is required. Without one this matched ordinary prose — an
    agent writing "cost: 500" about an approach it was weighing booked $500 to the
    run. Structured harness output goes through ``meter_value`` instead and needs
    no marker; this heuristic only ever sees unstructured lines.
    """
    match = re.search(
        r"(?:cost|price)\s*[=:]\s*(?:\$\s*([0-9]+(?:\.[0-9]+)?)"
        r"|([0-9]+(?:\.[0-9]+)?)\s*(?:usd|dollars?)\b)",
        text,
        re.I,
    )
    return float(match.group(1) or match.group(2)) if match else 0.0
