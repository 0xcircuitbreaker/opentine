"""A stdlib mutation fuzzer for the format readers (0.53, 1.0 criterion 1).

One engine drives every target in :mod:`opentine._fuzz_targets`: OTLP ingest,
the ``.tine`` v4/v5 reader, the pack readers (TINEPACK3/4/5), the local pack
(storage v3, codec 3) reader and the DSSE envelope verifiers. A seed is a
tuple of byte strings (most targets take one part; a local pack takes the
index, the pack and its dictionaries); each mutation changes one part.

The oracle is per target: an input either reads or is refused with one of
the target's documented refusal types (``ValueError`` and its ``KernelError``
/ ``UnicodeDecodeError`` / ``JSONDecodeError`` kin, ``RecursionError``).
Anything else is a crash. An input slower than ``SLOW_SECONDS`` is reported
apart: the long run fails on it, the in-suite run does not.

``scripts/fuzz.py`` drives it (CI: an iteration count; the 72-hour run:
``OPENTINE_FUZZ_HOURS=72``). Crash inputs are framed with :func:`frame` so a
multi-part input is one ``.bin`` file, read back with :func:`unframe`.
"""

from __future__ import annotations

import json
import random
import time
import traceback
from collections.abc import Callable
from dataclasses import dataclass, field

from opentine._otlp_fuzz import _len, _varint

SLOW_SECONDS = 5.0
_FRAME = b"TINEFUZZ1\0"
Parts = tuple[bytes, ...]


def frame(parts: Parts) -> bytes:
    """One file for a (possibly multi-part) input; a single part is stored bare."""
    if len(parts) == 1 and not parts[0].startswith(_FRAME):
        return parts[0]
    return _FRAME + b"".join(_varint(len(part)) + part for part in parts)


def unframe(data: bytes) -> Parts:
    if not data.startswith(_FRAME):
        return (data,)
    parts, at = [], len(_FRAME)
    while at < len(data):
        size, shift = 0, 0
        while True:
            if at >= len(data):
                raise ValueError("truncated fuzz frame")
            byte = data[at]
            at += 1
            size |= (byte & 0x7F) << shift
            shift += 7
            if not byte & 0x80:
                break
        if at + size > len(data):
            raise ValueError("truncated fuzz frame")
        parts.append(data[at : at + size])
        at += size
    return tuple(parts)


_ODD = (None, True, -1, 0, 2**63, 1e308, "", "\x00", "sha256:" + "0" * 64, [], {}, [[[]]])


def _json_mutate(rng: random.Random, value: object, depth: int = 0) -> object:
    """Replace, drop or duplicate one node of a parsed JSON document."""
    if isinstance(value, dict) and value and depth < 12 and rng.random() < 0.8:
        key = rng.choice(sorted(value))
        out = dict(value)
        roll = rng.random()
        if roll < 0.1:
            del out[key]
        elif roll < 0.15:
            out[key + "x"] = out[key]
        else:
            out[key] = _json_mutate(rng, value[key], depth + 1)
        return out
    if isinstance(value, list) and value and depth < 12 and rng.random() < 0.8:
        at = rng.randrange(len(value))
        out = list(value)
        roll = rng.random()
        if roll < 0.1:
            del out[at]
        elif roll < 0.2:
            out.insert(at, out[at])
        else:
            out[at] = _json_mutate(rng, value[at], depth + 1)
        return out
    if isinstance(value, str) and value and rng.random() < 0.5:
        at = rng.randrange(len(value))
        return value[:at] + rng.choice("0aZ=+/\x00é:") + value[at + 1 :]
    if isinstance(value, int) and not isinstance(value, bool) and rng.random() < 0.5:
        return value + rng.choice((-1, 1, 1 << 32))
    return rng.choice(_ODD)


def _byte_mutate(rng: random.Random, data: bytes, pool: list[bytes]) -> bytes:
    buf = bytearray(data)
    for _ in range(rng.randint(1, 6)):
        choice = rng.randrange(8)
        at = rng.randrange(len(buf) + 1)
        if choice == 0 and buf:
            buf[min(at, len(buf) - 1)] ^= 1 << rng.randrange(8)
        elif choice == 1:
            buf[at:at] = bytes([rng.randrange(256)])
        elif choice == 2 and buf:
            del buf[at : at + rng.randint(1, 64)]
        elif choice == 3:
            buf[at:at] = _varint(rng.choice((0, 1, 127, 128, 2**31, 2**63, 2**64 - 1)))
        elif choice == 4 and pool:
            other = rng.choice(pool)
            cut = rng.randrange(len(other) + 1)
            buf[at:] = other[cut:]
        elif choice == 5:
            buf[at:at] = _len(rng.randint(1, 15), bytes(buf[at : at + rng.randint(0, 64)]))
        elif choice == 6 and buf:
            buf[min(at, len(buf) - 1)] = rng.choice((0x00, 0x7F, 0x80, 0xFF, 0x22, 0x7B))
        elif choice == 7 and buf:
            del buf[rng.randrange(len(buf)) :]  # truncation
    return bytes(buf)


def mutate(rng: random.Random, parts: Parts, pools: list[list[bytes]]) -> Parts:
    """One mutated input: a single part changed, structurally when it is JSON."""
    index = rng.randrange(len(parts))
    data = parts[index]
    if data[:1] in (b"{", b"[") and rng.random() < 0.6:
        try:
            for _ in range(rng.randint(1, 3)):
                data = json.dumps(_json_mutate(rng, json.loads(data))).encode()
        except (ValueError, RecursionError, TypeError):
            data = _byte_mutate(rng, data, pools[index])
    else:
        data = _byte_mutate(rng, data, pools[index])
    return (*parts[:index], data, *parts[index + 1 :])


@dataclass
class Report:
    target: str
    iterations: int = 0
    crashes: list[dict[str, str]] = field(default_factory=list)
    slowest: float = 0.0
    slow: list[dict[str, str]] = field(default_factory=list)


def check(run: Callable[[Parts], None], refusals: tuple[type[BaseException], ...],
          parts: Parts) -> str | None:  # fmt: skip
    """The traceback of a crash on *parts*, or ``None`` for a read or a refusal."""
    try:
        run(parts)
    except refusals:
        return None
    except Exception:  # noqa: BLE001 - the oracle: anything else is a crash
        return traceback.format_exc()
    return None


def fuzz(
    target: str, seeds: list[Parts], *, seed: int, iterations: int | None = None,
    seconds: float | None = None, on_crash: Callable[[str, Parts, str], None] | None = None,
    watch: list[object] | None = None,
) -> Report:  # fmt: skip
    """Mutate *seeds* through *target* until *iterations* or *seconds* run out.

    *watch*, when given, holds ``[started, parts]`` while an input runs (and
    ``[None, None]`` between inputs) so a watchdog thread can save an input that
    hangs; a hung reader cannot be interrupted from Python, only reported.
    """
    from opentine._fuzz_targets import TARGETS

    spec = TARGETS[target]
    if not seeds:
        raise ValueError(f"no seeds for fuzz target {target}")
    rng, report = random.Random(seed), Report(target)
    width = max(len(parts) for parts in seeds)
    pools = [[p[i] for p in seeds if i < len(p)] for i in range(width)]
    deadline = time.monotonic() + seconds if seconds is not None else None
    while True:
        if iterations is not None and report.iterations >= iterations:
            return report
        if deadline is not None and time.monotonic() >= deadline:
            return report
        parts = mutate(rng, rng.choice(seeds), pools)
        started = time.perf_counter()
        if watch is not None:
            watch[:] = [time.monotonic(), parts]
        trace = check(spec.run, spec.refusals, parts)
        elapsed = time.perf_counter() - started
        if watch is not None:
            watch[:] = [None, None]
        if trace is not None:
            report.crashes.append({"input": frame(parts).hex(), "trace": trace})
            if on_crash:
                on_crash(target, parts, trace)
        report.slowest = max(report.slowest, elapsed)
        if elapsed > SLOW_SECONDS:
            report.slow.append({"input": frame(parts).hex(), "trace": "slow"})
        for index, part in enumerate(parts):
            if len(part) < 1 << 16 and rng.random() < 0.02:
                pools[index].append(part)
                del pools[index][: max(0, len(pools[index]) - 256)]
        report.iterations += 1


__all__ = ["SLOW_SECONDS", "Report", "check", "frame", "fuzz", "mutate", "unframe"]
