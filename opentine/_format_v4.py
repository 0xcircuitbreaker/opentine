"""Format v4 constants and the value checks both of its halves share.

A v4 ``.tine`` artifact is one RFC 8785 (JCS) object bundling the v3 envelopes
of a run (SPEC Part 9). Its canonical form is ``kernel.canonical_json``, which
refuses integers beyond 2**53-1 and non-finite floats. The legacy v3 repository
writer quietly stringifies both (``json_safe``); a v4 write refuses them instead,
so a run never changes meaning on its way into an artifact.

Since 0.42 v5 (SPEC Part 10: v4 with UTF-8 text blobs spelled as text, same
oids, root and signatures) is the default ``.tine`` writer; ``OPENTINE_FORMAT=4``,
``tine --format 4`` or ``tine --for-legacy`` write v4 for readers before 0.40.
``OPENTINE_FORMAT=2`` (or ``3``) or ``tine --format 2`` selects the deprecated
legacy writers (v2 ``.tine`` files, object-format-3 repositories) and prints one
deprecation warning.

Imports nothing from ``graph`` or ``repository``: ``migrations`` and
``_artifact_io`` both import it.
"""

from __future__ import annotations

import contextlib
import contextvars
import math
import os
import sys
from collections.abc import Iterator
from typing import Any

ARTIFACT_V4_VERSION = 4
ARTIFACT_V4_KIND = "tine-artifact/4"
#: The writer switch. ``4`` writes v4, ``2`` or ``3`` select the deprecated legacy
#: writers; unset (or ``5``, or anything else) writes format v5.
FORMAT_ENV = "OPENTINE_FORMAT"
#: The values that select the legacy writers: v2 artifacts, v3 repositories.
LEGACY_FORMATS = frozenset({2, 3})
#: Annotation envelopes one artifact may carry (one chain, oldest first).
MAX_V4_ANNOTATIONS = 1024
#: Envelopes one artifact may hold. Its own bound (not the network pack bound):
#: the 256 MiB artifact byte cap is the real ceiling; reader and writer share it.
MAX_V4_OBJECTS = 1_000_000
MAX_SAFE_INTEGER = 9_007_199_254_740_991
#: ``upgraded_from`` is not among them: it lives in the run payload (SPEC 9.9).
V4_KEYS = frozenset({"annotations", "format_version", "kind", "objects", "root", "signatures"})


_OVERRIDE: contextvars.ContextVar[int | None] = contextvars.ContextVar(
    "opentine_write_format", default=None
)
_WARNED: list[bool] = []
DEPRECATION = (
    "opentine: warning: format {n} writers are deprecated (OPENTINE_FORMAT / --format); "
    "the default is format v5, which needs opentine >= 0.40 to read\n"
)


class V4Unrepresentable(ValueError):
    """A run v4 cannot hold for a structural reason (a dangling step reference,
    too many objects). The default writer falls back to v2; strict v4 refuses."""


def fall_back_to_v2(run: Any, reason: Exception) -> None:
    """Warn on stderr and note in ``metadata.warnings``: saved as format 2.
    Under strict v4 (``OPENTINE_FORMAT=4``) re-raise *reason* instead."""
    if strict_v4():
        raise reason
    text = f"{reason}; saved as format 2"
    sys.stderr.write(f"opentine: warning: {text}\n")
    metadata = getattr(run, "metadata", None)
    if isinstance(metadata, dict):
        listed = metadata.setdefault("warnings", [])
        if not isinstance(listed, list):
            listed = metadata["warnings"] = [str(listed)]
        if text not in listed:
            listed.append(text)


def writer_format() -> int:
    """The format the writers use: 5 by default (SPEC Part 10), 4 when chosen
    (``--format 4``, ``--for-legacy``), 2 when a legacy one is chosen."""
    override = _OVERRIDE.get()
    if override is None:
        text = os.environ.get(FORMAT_ENV, "").strip()
        override = int(text) if text in {"2", "3", "4"} else None
    if override in LEGACY_FORMATS:
        return 2
    return ARTIFACT_V4_VERSION if override == ARTIFACT_V4_VERSION else 5


def v4_requested() -> bool:
    """True unless a legacy writer was chosen: v5 (the default) or v4."""
    return writer_format() >= ARTIFACT_V4_VERSION


def strict_v4() -> bool:
    """``OPENTINE_FORMAT=4`` spelled out: no legacy fallback anywhere (no
    ``tine-sig/2`` over a v2 dict, no HMAC ``tine-attest/1``)."""
    return _OVERRIDE.get() is None and os.environ.get(FORMAT_ENV, "").strip() == "4"


def format_arg(text: str) -> int:
    """``tine --format N``: 5 (the default, SPEC Part 10), 4 (readers before
    0.40) or the deprecated 2 (or 3)."""
    import argparse

    value = text.strip().lower().removeprefix("v")
    if value not in {"2", "3", "4", "5"}:
        raise argparse.ArgumentTypeError(f"choose 5, 4 or 2 (deprecated), not {text!r}")
    return int(value)


def add_writer_args(parser: Any) -> None:
    """The global ``--format N`` and ``--for-legacy`` (``--format 4``) flags."""
    writer = parser.add_mutually_exclusive_group()
    writer.add_argument(
        "--format", dest="write_format", type=format_arg, metavar="{2,4,5}", default=None,
        help="Writer format: 5 (default; opentine >=0.40 reads), 4 (older readers), 2 (deprecated)",
    )  # fmt: skip
    writer.add_argument(
        "--for-legacy", dest="write_format", action="store_const", const=ARTIFACT_V4_VERSION,
        help="Write .tine v4 for readers before 0.40 (same as --format 4)",
    )  # fmt: skip


@contextlib.contextmanager
def write_format(version: int | None) -> Iterator[None]:
    """Pin the writer format for the block (``tine --format``, ``migrate --to 2``)."""
    token = _OVERRIDE.set(version)
    try:
        yield
    finally:
        _OVERRIDE.reset(token)


def v5_if_requested(encoded: bytes) -> bytes:
    """Canonical v4 artifact bytes, re-spelled as v5 unless v4 was chosen."""
    if writer_format() != 5:
        return encoded
    from opentine._artifact_io import parse_artifact_json
    from opentine._tine_v5 import to_v5
    from opentine.kernel import canonical_json

    return canonical_json(to_v5(parse_artifact_json(encoded)))


def warn_legacy() -> None:
    """One deprecation warning per process, on stderr, when a legacy writer writes."""
    if _WARNED:
        return
    _WARNED.append(True)
    override = _OVERRIDE.get()
    shown = override if override is not None else os.environ.get(FORMAT_ENV, "2").strip()
    sys.stderr.write(DEPRECATION.format(n=shown))


def is_v4_artifact(data: Any) -> bool:
    """Detect a v4 bundle by its version *and* kind, never by one alone."""
    return (
        isinstance(data, dict)
        and data.get("format_version") == ARTIFACT_V4_VERSION
        and type(data.get("format_version")) is int
        and data.get("kind") == ARTIFACT_V4_KIND
    )


def _children(value: Any, path: str) -> list[tuple[Any, str]]:
    if isinstance(value, dict):
        return [(item, f"{path}.{key}") for key, item in value.items()]
    if isinstance(value, (list, tuple)):
        return [(item, f"{path}[{index}]") for index, item in enumerate(value)]
    return []


def refuse_unrepresentable(value: Any, where: str = "run") -> None:
    """Refuse what v4's canonical form cannot hold, naming the field.

    Iterative on purpose (an explicit stack, no recursion): the same walk must
    finish on any structure the reader's depth bound admits.
    """
    stack = [(value, where)]
    while stack:
        item, path = stack.pop()
        if isinstance(item, bool):
            continue
        if isinstance(item, int) and abs(item) > MAX_SAFE_INTEGER:
            raise ValueError(
                f"{path} holds a {item.bit_length()}-bit integer, beyond 2**53-1: "
                "format v4 refuses it rather than round or stringify it; store it as a "
                f"string, or set {FORMAT_ENV}=2 to write deprecated format v2"
            )
        if isinstance(item, float) and not math.isfinite(item):
            raise ValueError(f"{path} holds {item!r}, which format v4 cannot represent")
        stack.extend(_children(item, path))
