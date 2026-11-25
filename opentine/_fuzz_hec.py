"""The ``hec`` fuzz target (0.81): one HEC1 body, decoded as ``TINEPACK6`` does.

An input is decoded with the ``opentine-1`` grammar under a small budget. The
oracle is stricter than "raises ``ValueError``": a refusal must be a
``HecError`` whose code is one of the published reason codes. An accepted input
is then checked differentially:

* the same pack decoded with the exact set of ids it produced must answer the
  same objects (the want-set rule agrees with the open decode), and
* the decoded objects re-encoded by the writer must decode to the same
  objects again (writer and reader agree on every accepted table).
"""

from __future__ import annotations

from opentine import _hec
from opentine._hec import _backend

#: Small budgets: a fuzz input never needs more, and a bomb is refused fast.
LIMITS = _hec.Limits(max_output_bytes=8 << 20, max_objects=1 << 16, max_unit_bytes=16 << 20)
SEEDS = "tests/vectors/tinepack6/packs"


def _decode(data: bytes, want) -> list[tuple[bytes, bytes, bytes]] | None:
    try:
        got = _hec.decode(data, _hec.OPENTINE, want, LIMITS)
    except _hec.HecError as exc:
        if exc.code not in _hec.REASON_CODES:
            raise AssertionError(f"unpublished reason code {exc.code!r}") from exc
        return None
    return [(o.id, o.type.desc, o.body) for o in got.objects]


def run_one(data: bytes) -> None:
    """Decode one input; any exception but a published refusal is a crash."""
    objects = _decode(data, _hec.ANY)
    if objects is None:
        return
    exact = _decode(data, {oid for oid, _, _ in objects})
    if exact != objects:
        raise AssertionError("the exact want-set decode disagrees with the open decode")
    codec = _backend.ZSTD if _backend.zstd_available() else _backend.ZLIB
    table = [(desc, body) for _, desc, body in objects]
    again = _hec.encode(table, _hec.OPENTINE, level=1, codec=codec, verify=False)
    if _decode(again, {oid for oid, _, _ in objects}) != objects:
        raise AssertionError("re-encoding the decoded objects does not round-trip")


__all__ = ["LIMITS", "SEEDS", "run_one"]
