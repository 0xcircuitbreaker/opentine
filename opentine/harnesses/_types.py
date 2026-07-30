"""Normalized harness records and parsing helpers."""

from __future__ import annotations

import json
import math
import re
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol

from opentine._canon_redact import MAX_CANONICAL_DEPTH, _too_deep
from opentine.core import StepKind, step_id
from opentine.kernel import MAX_JSON_DEPTH, KernelError, validate_json_shape


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


def _jsonable(value: Any, _depth: int = 0) -> Any:
    """Coerce a harness result to JSON shapes, refusing what no build can encode.

    A distinct walk from ``_canon._jsonable`` (this one keeps key order and renders
    unknown objects with ``repr``), and it needs the same bound for the same
    reason: a harness result is external data — a subprocess's stdout, an SDK
    object graph — and unbounded this recursed as deep as that data, dying with
    ``RecursionError`` at ~496 levels on 3.11 against ~995 on 3.12+ because before
    PEP 709 a comprehension cost a second frame per level. So an agent result
    nested 600 deep recorded a step on 3.12 and killed the run on the support
    floor. Both branches are statement loops now: one frame per level everywhere,
    one explicit refusal, shared with the walk that canonicalizes the step next.

    The ``repr`` fallback below is a knowingly remaining residual: its recursion
    happens inside the *caller's own* ``__repr__`` (a chain of dataclasses tops out
    at 331 levels on 3.11 and 498 on 3.12+), which no bound here can reach, and the
    identical fallback sits in ``_canon._jsonable``. Reaching it needs a 300-deep
    object graph rather than 300-deep JSON, so it is not constructible from a
    subprocess's output the way every branch above is.
    """
    if _depth > MAX_CANONICAL_DEPTH:
        raise _too_deep()
    if value is None or isinstance(value, str | int | float | bool):
        return value
    if isinstance(value, Mapping):
        coerced: dict[str, Any] = {}
        for key, item in value.items():
            coerced[str(key)] = _jsonable(item, _depth + 1)
        return coerced
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        items: list[Any] = []
        for item in value:
            items.append(_jsonable(item, _depth + 1))
        return items
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
    """Parse one harness stdout line as an event, or ``None`` if it is not one.

    ``json.loads`` recurses over nesting in C, and how much of the 1000-unit
    recursion budget a C call spends changed in 3.12: the same subprocess line
    parsed past 8000 levels on 3.12+ and raised an uncaught ``RecursionError`` at
    ~990 on 3.11, where only ``JSONDecodeError`` is caught below — so a hostile or
    merely broken harness could kill a run on the support floor and not elsewhere.
    Nothing deeper than the reader's bound can be stored in either format anyway,
    so past it the line is not an event and is recorded as text like any other
    unparseable output. The bracket count gates the check: it cannot understate the
    depth, so the reader's ``O(n)`` scan (~60ms per MB, against 2ms for
    ``json.loads``) never runs for an ordinary line — only for one carrying more
    than ``MAX_JSON_DEPTH`` brackets, which is either genuinely over the bound or
    quoting a lot of code. Reusing that scan rather than counting depth here keeps
    one depth rule in the codebase.
    """
    stripped = line.strip()
    if not stripped.startswith("{"):
        return None
    if stripped.count("[") + stripped.count("{") > MAX_JSON_DEPTH:
        try:
            # Tokens cannot outnumber characters, so this bounds depth only: a
            # legitimately huge-but-flat event line must still parse.
            validate_json_shape(stripped, max_tokens=len(stripped) + 1)
        except KernelError:
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
