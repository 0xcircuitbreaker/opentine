"""Pack frames whose bytes do not depend on which zlib built them.

A frame is ``TINEPACK3`` magic, the inflated body's SHA-256, then a zlib stream.
The format fixes the body and its digest; the stream is the compressor's
choice, and implementations disagree on it -- CPython 3.14's Windows build
ships zlib-ng, which deflates the 790 KB shallow-bound frames to different bytes
than classic zlib, so regenerating the suite there changed two committed files.

:func:`stable_frame` returns the committed frame (a ``frames/*.pack`` file or a
frame inlined as ``bytes_b64`` in a vector) that inflates to the same header and
body, and the freshly built bytes otherwise. Regeneration is then byte-identical
under any zlib, while a frame whose *content* changed still regenerates -- and
the drift gate still catches it.
"""

from __future__ import annotations

import base64
import functools
import json
import zlib
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from opentine.repository.pack import MAGIC

SUITE = Path(__file__).resolve().parents[2] / "docs" / "conformance"
#: Magic plus the 32-byte body digest: everything before the zlib stream.
HEADER = len(MAGIC) + 32


def _inflated(frame: bytes) -> bytes | None:
    try:
        return zlib.decompress(frame[HEADER:])
    except zlib.error:
        return None


def _inline_frames(node: Any) -> Iterator[bytes]:
    if isinstance(node, dict):
        value = node.get("bytes_b64")
        if isinstance(value, str):
            raw = base64.b64decode(value)
            if raw.startswith(MAGIC):
                yield raw
        for item in node.values():
            yield from _inline_frames(item)
    elif isinstance(node, list):
        for item in node:
            yield from _inline_frames(item)


@functools.cache
def _committed() -> dict[tuple[bytes, bytes], bytes]:
    found = [path.read_bytes() for path in sorted((SUITE / "frames").glob("*.pack"))]
    for path in sorted((SUITE / "vectors").glob("*.json")):
        found.extend(_inline_frames(json.loads(path.read_text("utf-8"))))
    index: dict[tuple[bytes, bytes], bytes] = {}
    for raw in found:
        if (body := _inflated(raw)) is not None:
            index.setdefault((raw[:HEADER], body), raw)
    return index


def stable_frame(raw: bytes) -> bytes:
    """The committed frame with *raw*'s header and inflated body, else *raw*."""
    body = _inflated(raw)
    if body is None:
        return raw
    return _committed().get((raw[:HEADER], body), raw)
