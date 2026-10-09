"""Bounds an import applies to raw bytes before any of them are parsed.

``tine import`` read a source up to its 256 MiB cap and handed it straight to
``json.loads``. A container costs ~2 bytes on disk but ~64 once materialized, so
a cap-sized ``[{},{},...]`` file needed ~6.6 GB of memory before the record-count
check could refuse it -- the amplification the ``.tine`` reader already makes
unprofitable with a structural-token budget relative to size. The same scan and
budget now run here, on every whole document and every JSONL line.

The byte cap itself was enforced only for regular files: a pipe, FIFO or device
reports ``st_size == 0`` and was then read whole, and a JSONL line on stdin was
buffered in full before its length was looked at. Every read is now bounded.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import IO, Any

from opentine._artifact_io import _structural_token_budget
from opentine.kernel import validate_json_shape


def shape_checked(data: bytes | str) -> bytes | str:
    """*data*, once its nesting and structural density are within budget."""
    validate_json_shape(data, max_tokens=_structural_token_budget(len(data)))
    return data


def bounded_read(handle: IO[Any], limit: int) -> bytes | str:
    """At most ``limit + 1`` units of *handle*, so the caller can refuse the excess."""
    data = handle.read(limit + 1)
    if len(data) > limit:
        raise ValueError("trace import exceeds aggregate payload limit")
    return data


def bounded_lines(handle: IO[Any], *, line_limit: int, total_limit: int) -> Iterator[Any]:
    """Lines of *handle*, never buffering more than ``line_limit + 1`` of one.

    An over-length line is drained in bounded pieces and skipped, as the JSONL
    importer always skipped one read from a path.
    """
    total = 0
    while line := handle.readline(line_limit + 1):
        total += len(line)
        if total > total_limit:
            raise ValueError("trace import exceeds aggregate payload limit")
        newline = b"\n" if isinstance(line, bytes) else "\n"
        oversized = len(line) > line_limit
        while oversized and not line.endswith(newline):
            line = handle.readline(line_limit + 1)
            total += len(line)
            if total > total_limit:
                raise ValueError("trace import exceeds aggregate payload limit")
            if not line:
                break
        if not oversized:
            yield line


__all__ = ["bounded_lines", "bounded_read", "shape_checked"]
