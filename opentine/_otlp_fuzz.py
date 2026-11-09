"""A stdlib mutation fuzzer for the OTLP protobuf ingest path (0.48).

The target is exactly what an OTLP/HTTP protobuf body or an OTLP/gRPC message
reaches: :func:`opentine._otlp_http.decode_protobuf` (the bounded wire reader,
the traces or logs decoder, the item caps) and then the GenAI span or log
importer. The oracle: every input either imports or is refused with a
``ValueError`` (``WireError``, ``_Refused``) or a ``RecursionError`` the
endpoints already answer as 400/413. Anything else -- an ``IndexError``, a
``TypeError``, a ``KeyError`` -- is a crash. An input taking longer than
``SLOW_SECONDS`` is reported apart (``Report.slow``): the script fails on it,
the in-suite run does not, as wall-clock time depends on the machine.

``scripts/fuzz_otlp.py`` drives it: a scaled run in CI (an iteration count), the
72-hour acceptance run by hand (``--hours 72``), and atheris when installed
(``--atheris``). Seeds are valid traces and logs requests built here.
"""

from __future__ import annotations

import random
import struct
import time
import traceback
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field

ROUTES = ("add_spans", "add_logs")
SLOW_SECONDS = 5.0


def _varint(value: int) -> bytes:
    value &= (1 << 64) - 1
    out = bytearray()
    while True:
        byte, value = value & 0x7F, value >> 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def _len(number: int, payload: bytes) -> bytes:
    return _varint(number << 3 | 2) + _varint(len(payload)) + payload


def _num(number: int, value: int) -> bytes:
    return _varint(number << 3) + _varint(value)


def _fixed64(number: int, value: int) -> bytes:
    return _varint(number << 3 | 1) + struct.pack("<Q", value)


def _kv(key: str, value: object) -> bytes:
    if isinstance(value, bool):
        any_value = _num(2, int(value))
    elif isinstance(value, int):
        any_value = _num(3, value)
    elif isinstance(value, list):
        any_value = _len(5, b"".join(_len(1, _len(1, str(v).encode())) for v in value))
    else:
        any_value = _len(1, str(value).encode())
    return _len(1, key.encode()) + _len(2, any_value)


ATTRIBUTES = {
    "gen_ai.operation.name": "chat",
    "gen_ai.system": "anthropic",
    "gen_ai.request.model": "claude-x",
    "gen_ai.usage.input_tokens": 12,
    "gen_ai.usage.output_tokens": 5,
    "session.id": "s-1",
    "custom.tags": ["a", "b"],
    "custom.flag": True,
}
LOG_ATTRIBUTES = {
    "session.id": "s-1",
    "model": "claude-x",
    "prompt": "hi",
    "input_tokens": 12,
    "output_tokens": 5,
    "cost_usd": "0.01",
}
START = 1_791_000_000 * 1_000_000_000


def traces_seed(spans: int = 2) -> bytes:
    body = b""
    for index in range(spans):
        span = _len(1, bytes.fromhex("ab" * 16)) + _len(2, bytes([index + 1]) * 8)
        if index:
            span += _len(4, b"\x01" * 8)
        span += _len(5, b"chat claude-x") + _num(6, 3)
        span += _fixed64(7, START + index) + _fixed64(8, START + index + 10**9)
        span += b"".join(_len(9, _kv(k, v)) for k, v in ATTRIBUTES.items())
        span += _len(11, _fixed64(1, START) + _len(2, b"gen_ai.user.message"))
        body += _len(2, span)
    resource = _len(1, _len(1, _kv("service.name", "agent")))
    return _len(1, resource + _len(2, _len(1, _len(1, b"scope")) + body))


def logs_seed(records: int = 2) -> bytes:
    body = b""
    for index in range(records):
        record = _fixed64(1, START + index) + _num(2, 9) + _len(3, b"INFO")
        record += _len(5, _len(1, b'{"role": "user", "content": "hi"}'))
        name = "claude_code.api_request" if index % 2 else "claude_code.user_prompt"
        record += _len(6, _kv("event.name", name))
        record += b"".join(_len(6, _kv(k, v)) for k, v in LOG_ATTRIBUTES.items())
        record += _len(9, bytes.fromhex("ab" * 16)) + _len(10, b"\x01" * 8)
        record += _len(12, name.encode())
        body += _len(2, record)
    resource = _len(1, _len(1, _kv("service.name", "agent")))
    return _len(1, resource + _len(2, _len(1, _len(1, b"scope")) + body))


def seeds() -> list[tuple[str, bytes]]:
    return [("add_spans", traces_seed(1)), ("add_spans", traces_seed(3)),
            ("add_logs", logs_seed(1)), ("add_logs", logs_seed(3)),
            ("add_spans", b""), ("add_logs", b"")]  # fmt: skip


def _mutations(rng: random.Random, data: bytes, pool: list[bytes]) -> Iterator[bytes]:
    buf = bytearray(data)
    for _ in range(rng.randint(1, 6)):
        choice = rng.randrange(8)
        at = rng.randrange(len(buf) + 1)
        if choice == 0 and buf:
            buf[min(at, len(buf) - 1)] ^= 1 << rng.randrange(8)
        elif choice == 1:
            buf[at:at] = bytes([rng.randrange(256)])
        elif choice == 2 and buf:
            del buf[at : at + rng.randint(1, 8)]
        elif choice == 3:
            buf[at:at] = _varint(rng.choice((0, 1, 127, 128, 2**31, 2**63, 2**64 - 1)))
        elif choice == 4 and pool:
            other = rng.choice(pool)
            cut = rng.randrange(len(other) + 1)
            buf[at:] = other[cut:]
        elif choice == 5:
            buf[at:at] = _len(rng.randint(1, 15), bytes(buf[at : at + rng.randint(0, 64)]))
        elif choice == 6 and buf:
            buf[min(at, len(buf) - 1)] = rng.choice((0x00, 0x7F, 0x80, 0xFF, 0x0A, 0x12))
        elif choice == 7:
            depth = rng.randint(1, 40)  # deep nesting around a fragment
            inner = bytes(buf[at : at + 16])
            for _ in range(depth):
                inner = _len(rng.choice((1, 2, 5, 6)), inner)
            buf[at:at] = inner
    yield bytes(buf)


def run_one(route: str, data: bytes) -> None:
    """The target: raises only for a crash."""
    from opentine._otlp_http import _Refused, decode_protobuf

    try:
        document = decode_protobuf(data, route)
        if route == "add_spans":
            from opentine.trace.importers import otel_genai_events

            otel_genai_events(document)
        else:
            from opentine.trace._otel_log_import import otel_log_events

            otel_log_events(document)
    except (_Refused, RecursionError, ValueError):
        return


@dataclass
class Report:
    iterations: int = 0
    crashes: list[dict[str, str]] = field(default_factory=list)
    slowest: float = 0.0
    #: Inputs slower than SLOW_SECONDS: a wall-clock signal for the long run, not a crash
    #: (machine load decides it, so the in-suite run never fails on it).
    slow: list[dict[str, str]] = field(default_factory=list)


def fuzz(
    *, seed: int, iterations: int | None = None, seconds: float | None = None,
    on_crash: Callable[[str, bytes, str], None] | None = None,
) -> Report:  # fmt: skip
    """Mutate the seeds until *iterations* or *seconds* run out."""
    rng, report, pool = random.Random(seed), Report(), [data for _, data in seeds()]
    deadline = time.monotonic() + seconds if seconds is not None else None
    while True:
        if iterations is not None and report.iterations >= iterations:
            return report
        if deadline is not None and time.monotonic() >= deadline:
            return report
        route, base = rng.choice(seeds())
        for data in _mutations(rng, rng.choice(pool) if rng.random() < 0.3 else base, pool):
            started = time.perf_counter()
            try:
                run_one(route, data)
            except Exception:  # noqa: BLE001 - the oracle: anything else is a crash
                found = {"route": route, "input": data.hex(), "trace": traceback.format_exc()}
                report.crashes.append(found)
                if on_crash:
                    on_crash(route, data, found["trace"])
            elapsed = time.perf_counter() - started
            report.slowest = max(report.slowest, elapsed)
            if elapsed > SLOW_SECONDS:
                report.slow.append({"route": route, "input": data.hex(), "trace": "slow"})
            if len(data) < 4096 and rng.random() < 0.05:
                pool.append(data)
                del pool[: max(0, len(pool) - 512)]
        report.iterations += 1


__all__ = ["ROUTES", "Report", "fuzz", "logs_seed", "run_one", "seeds", "traces_seed"]
