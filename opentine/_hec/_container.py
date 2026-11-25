"""The HEC1 container: magic, grammar name, then sixteen streams in fixed order.

Each stream is ``codec(1) uv(raw_len) [uv(comp_len)] bytes``. Reading is two-pass
(SPEC "TINEPACK6", HEC1 check order): pass 1 reads only the frame headers and
checks the declared sizes; the head alone is inflated and its counts checked
against the caller's budget; only then is anything else inflated, each stream
capped at its declared raw length.
"""

from __future__ import annotations

from opentine._hec import _backend as backend
from opentine._hec._core import (
    MAGIC,
    STREAMS,
    HecError,
    Limits,
    Reader,
    head_cap,
    stream_bound,
    uv,
)


def write(streams: dict[str, bytearray], grammar_name: bytes, codec: int, level: int) -> bytes:
    """A stream that does not shrink is stored."""
    out = [MAGIC, uv(len(grammar_name)), grammar_name]
    for name in STREAMS:
        raw = bytes(streams[name])
        packed = b""
        if raw and codec != backend.STORED:
            packed = backend.compress(codec, raw, level)
        if not raw or codec == backend.STORED or len(packed) + len(uv(len(packed))) >= len(raw):
            out += [bytes([backend.STORED]), uv(len(raw)), raw]
        else:
            out += [bytes([codec]), uv(len(raw)), uv(len(packed)), packed]
    return b"".join(out)


def _inflate(name: str, codec: int, raw_len: int, data: bytes, limits: Limits) -> bytes:
    if codec == backend.STORED:
        return data
    try:
        return backend.decompress(codec, data, raw_len, limits.max_window_log)
    except backend.BackendError as exc:
        raise HecError("backend", f"{name}: {exc}") from None


def read(pack: bytes, grammar_name: bytes, limits: Limits) -> dict[str, bytes]:
    """``{stream name: raw bytes}``; declared sizes are checked before inflation."""
    r = Reader(pack, "container")
    if r.take(4) != MAGIC:
        raise HecError("header", "bad magic")
    k = r.uv()
    if k > 64 or r.take(k) != grammar_name:
        raise HecError("header", f"pack is not for grammar {grammar_name!r}")
    frames: list[tuple[str, int, int, bytes]] = []
    total = 0
    for name in STREAMS:
        codec = r.take(1)[0]
        raw_len = r.uv()
        total += raw_len
        if total > limits.max_stream_bytes:
            raise HecError("budget", "declared stream bytes exceed the budget")
        data = r.take(raw_len) if codec == backend.STORED else r.take(r.uv())
        frames.append((name, codec, raw_len, data))
    if not r.done():
        raise HecError("trailing", "bytes after the last stream")
    raw = {f[0]: f[2] for f in frames}
    if raw["head"] > head_cap(limits):
        raise HecError("budget", "declared head exceeds the head cap")
    if raw["aux"] > limits.max_aux_bytes:
        raise HecError("limit", "aux bytes")
    streams = {"head": _inflate(*frames[0], limits)}
    h = Reader(streams["head"], "head")
    n_obj, total_out, n_types = h.uv(), h.uv(), h.uv()
    check_head(n_obj, total_out, n_types, limits)
    body = sum(f[2] for f in frames if f[0] not in ("head", "aux"))
    if body > stream_bound(total_out, n_obj):
        raise HecError("budget", "declared stream bytes exceed the bound for the declared output")
    for frame in frames[1:]:
        streams[frame[0]] = _inflate(*frame, limits)
    return streams


def check_head(n_obj: int, total_out: int, n_types: int, limits: Limits) -> None:
    if n_obj > limits.max_objects:
        raise HecError("limit", "objects")
    if total_out > limits.max_output_bytes:
        raise HecError("budget", "declared output exceeds the caller budget")
    if n_types > limits.max_types or n_types > n_obj:
        raise HecError("limit", "types")
    # ids are a function of (type, body) and duplicates are refused: one empty object per type
    if n_obj > total_out + n_types:
        raise HecError("budget", "more objects than the declared output allows")
