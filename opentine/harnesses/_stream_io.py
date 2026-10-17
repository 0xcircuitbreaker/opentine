"""Reading a harness subprocess's two output streams, line by line, bounded.

Split out of :mod:`opentine.harnesses._process` for the module line cap when
stderr got its own pipe. :func:`pump` is one stream's read loop: each stdout
line is key-masked first (:class:`~opentine.harnesses._key_mask.KeyLines`),
then bounded, buffered and parsed. stderr is read on its own pipe and is never
parsed as structured events: a JSON line there comes from whatever the CLI let
write to it (an MCP server, a hook), not from the CLI's event stream.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass, field
from io import StringIO

from opentine.harnesses._key_mask import PLACEHOLDER, KeyLines, buffered
from opentine.harnesses._types import HarnessStep


@dataclass
class Budget:
    """Output limits shared by both streams of one subprocess."""

    name: str
    max_chars: int
    max_events: int
    chars: int = 0
    events: int = 0
    seen: dict[str, bool] = field(default_factory=dict)

    def add_line(self, stream: str, line: str) -> None:
        self.chars += (1 if self.seen.get(stream) else 0) + len(line)
        self.seen[stream] = True
        if self.chars > self.max_chars:
            raise RuntimeError(f"{self.name} output exceeds {self.max_chars} characters")

    def add_event(self) -> None:
        self.events += 1
        if self.events > self.max_events:
            raise RuntimeError(f"{self.name} emitted more than {self.max_events} events")


#: What a malformed CLI event can raise from a parser; ``ArithmeticError``
#: covers a JSON integer too large for a float (final pass 5, #10).
_MALFORMED = (TypeError, ValueError, KeyError, AttributeError, IndexError, ArithmeticError)


async def pump(
    stream: asyncio.StreamReader,
    *,
    stream_name: str,
    budget: Budget,
    buffer: StringIO,
    parse: Callable[[str], HarnessStep | list[HarnessStep] | None],
    emit: Callable[[HarnessStep], object] | None,
    max_line_bytes: int,
) -> None:
    """Read *stream* to EOF: mask, bound, buffer, parse, and emit each line."""
    keys = KeyLines()
    while True:
        try:
            raw = await stream.readline()
        except ValueError as exc:
            label = "output" if stream_name == "stdout" else stream_name
            raise RuntimeError(
                f"{budget.name} {label} line exceeds {max_line_bytes} bytes"
            ) from exc
        if not raw:
            return
        text = raw.decode(errors="replace").rstrip("\r\n")
        line = keys.mask(text)
        separator = budget.seen.get(stream_name, False)
        # The joined output keeps a raw text line's key markers for the record's
        # scrubber; steps always get the masked line (final pass 5, #9). The cap
        # charges whichever is longer: charging only the masked form let a 1 MB
        # line behind a marker cost 22 characters (final pass 6, #7).
        kept = buffered(keys, text, line)
        budget.add_line(stream_name, kept if len(kept) > len(line) else line)
        if separator:
            buffer.write("\n")
        buffer.write(kept)
        try:
            parsed = parse(line)
        except _MALFORMED as exc:
            # A malformed event must not end the run it describes: every later
            # event, the CLI's closing cost included, was lost (final pass 2, #9).
            parsed = HarnessStep(
                kind="think", inputs={"text": line, "parse_error": type(exc).__name__}
            )
        # One output line can carry several steps (parallel tool results).
        for step in parsed if isinstance(parsed, list) else [parsed] if parsed else []:
            budget.add_event()
            if emit:
                try:
                    emit(step)
                except ValueError as exc:
                    # A value the record refuses (an unsafe count, a non-finite
                    # number) must not end the run either (final pass 6, #9/#10),
                    # nor may a refusal of the fallback -- an autosave failing the
                    # same way -- kill the agent (final pass 8, #5).
                    with suppress(ValueError):
                        emit(
                            HarnessStep(
                                kind="think",
                                inputs={"text": line, "record_error": type(exc).__name__},
                            )
                        )


def stderr_step(line: str, model_info: str | None) -> HarnessStep | None:
    """A stderr line as recorded text: never an event, never a charge."""
    if not line:
        return None
    return HarnessStep(
        kind="think", inputs={"text": line, "stream": "stderr"}, model_info=model_info
    )


__all__ = ["PLACEHOLDER", "Budget", "KeyLines", "pump", "stderr_step"]
