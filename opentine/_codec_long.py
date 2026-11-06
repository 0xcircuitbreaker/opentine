"""zstd long-distance mode: one stream flushed in blocks, its window capped (X17).

A writer compresses a sequence of blocks as one zstd frame with long-distance
matching and ``window_log`` :data:`WINDOW_LOG` (128 MiB), flushing at each
block's end so a reader inflates the blocks in order and checks each one's
length as it goes. Matches reach back across blocks, which is where similar
runs with growing histories find their repetition.

A reader caps the decoder window at :data:`WINDOW_LOG`: a frame that asks for a
larger window is refused before anything is allocated for it, so a crafted
input cannot make a reader reserve gigabytes.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator

from opentine._codec import CodecError, _zstd

#: The long-mode window, and the largest window any reader accepts.
WINDOW_LOG = 27
#: The wire level (``ROADMAP`` §4, L4).
WIRE_LEVEL = 9


def available() -> bool:
    return _zstd() is not None


def _module():
    module = _zstd()
    if module is None:
        raise CodecError("long-mode packs need zstd; install opentine[zstd]")
    return module


def compress_blocks(blocks: Iterable[bytes], level: int = WIRE_LEVEL) -> list[bytes]:
    """Each block's compressed bytes, together one long-mode zstd frame.

    *blocks* must hold at least one (possibly empty) block.
    """
    module = _module()
    param = module.CompressionParameter
    engine = module.ZstdCompressor(
        options={
            param.compression_level: level,
            param.window_log: WINDOW_LOG,
            param.enable_long_distance_matching: 1,
            param.checksum_flag: 1,
        }
    )
    out = [engine.compress(block, mode=engine.FLUSH_BLOCK) for block in blocks]
    if not out:
        raise CodecError("a long-mode frame needs at least one block")
    out[-1] += engine.flush(mode=engine.FLUSH_FRAME)  # the frame's end and checksum
    return out


def decompress_blocks(frames: Iterable[tuple[bytes, int]]) -> Iterator[bytes]:
    """Inflate ``(compressed, raw size)`` blocks of one frame, in order.

    Each block must inflate to exactly its declared size, at most that much is
    ever produced, and the frame must end with the last block. A window larger
    than :data:`WINDOW_LOG` is refused.
    """
    module = _module()
    engine = module.ZstdDecompressor(
        options={module.DecompressionParameter.window_log_max: WINDOW_LOG}
    )
    try:
        for chunk, size in frames:
            if engine.eof:
                raise CodecError("long-mode frame ends before its last block")
            out = engine.decompress(chunk, max_length=size + 1)
            if len(out) != size:
                raise CodecError("long-mode block does not match its declared size")
            yield out
    except module.ZstdError as exc:
        raise CodecError(f"long-mode frame is corrupt or oversized: {exc}") from exc
    if not engine.eof or engine.unused_data:
        raise CodecError("long-mode frame has trailing or missing data")


__all__ = ["WINDOW_LOG", "WIRE_LEVEL", "available", "compress_blocks", "decompress_blocks"]
