"""Byte back ends for HEC streams: stored (0), zstd (1, magicless frame), zlib (2).

Every decompressor is told the exact raw length, refuses anything that would
produce more or less, and refuses input with bytes left over. zstd frames are
checked from their header (exact frame length, content size, window, no
dictionary) before anything is inflated. zstd comes from the stdlib
(``compression.zstd``) or ``backports.zstd`` (``opentine[zstd]``); without it
zstd streams are refused and writers use zlib.
"""

from __future__ import annotations

import zlib

from opentine._codec import _zstd

STORED, ZSTD, ZLIB = 0, 1, 2
_MAGIC = b"\x28\xb5\x2f\xfd"
#: The largest window an encoder uses: the default reader cap (``max_window_log``).
ENCODE_WINDOW_LOG = 27


class BackendError(ValueError):
    pass


def zstd_available() -> bool:
    return _zstd() is not None


def compress(codec: int, raw: bytes, level: int = 19) -> bytes:
    if codec == ZSTD:
        module = _zstd()
        if module is None:
            raise BackendError("zstd is not available; install opentine[zstd]")
        window_log = min(ENCODE_WINDOW_LOG, max(20, (max(len(raw), 2) - 1).bit_length()))
        param = module.CompressionParameter
        engine = module.ZstdCompressor(
            options={
                param.compression_level: level,
                param.window_log: window_log,
                param.enable_long_distance_matching: 1,
                param.content_size_flag: 1,
                param.checksum_flag: 0,
            }
        )
        frame = engine.compress(raw, mode=engine.FLUSH_FRAME)
        return frame[len(_MAGIC) :]
    if codec == ZLIB:
        return zlib.compress(raw, 9)
    if codec == STORED:
        return raw
    raise BackendError(f"unknown codec {codec!r}")


def _frame_header(comp: bytes) -> tuple[int, int | None, int, int, bool]:
    """``(header size, content size, window size, dictionary id, checksum)``."""
    if not comp:
        raise BackendError("bad frame")
    fhd = comp[0]
    fcs_flag, single, has_ck, did_flag = fhd >> 6, (fhd >> 5) & 1, (fhd >> 2) & 1, fhd & 3
    if fhd & 0x08:
        raise BackendError("bad frame")  # reserved bit
    did_size = (0, 1, 2, 4)[did_flag]
    fcs_size = (1 if single else 0, 2, 4, 8)[fcs_flag]
    size = 1 + (0 if single else 1) + did_size + fcs_size
    if len(comp) < size:
        raise BackendError("bad frame")
    p = 1
    window = 0
    if not single:
        wd = comp[p]
        p += 1
        base = 1 << (10 + (wd >> 3))
        window = base + (base >> 3) * (wd & 7)
    did = int.from_bytes(comp[p : p + did_size], "little")
    p += did_size
    content: int | None = None
    if fcs_size:
        content = int.from_bytes(comp[p : p + fcs_size], "little")
        if fcs_size == 2:
            content += 256
    if single:
        window = content or 0
    return size, content, window, did, bool(has_ck)


def _frame_length(comp: bytes, header: int, has_ck: bool) -> int:
    """Exact length of the frame: header, blocks up to the last, checksum."""
    p = header
    while True:
        if p + 3 > len(comp):
            raise BackendError("bad frame")
        bh = int.from_bytes(comp[p : p + 3], "little")
        p += 3
        last, btype, bsize = bh & 1, (bh >> 1) & 3, bh >> 3
        if btype == 3:
            raise BackendError("bad frame")
        p += 1 if btype == 1 else bsize
        if p > len(comp):
            raise BackendError("bad frame")
        if last:
            break
    if has_ck:
        p += 4
        if p > len(comp):
            raise BackendError("bad frame")
    return p


def _inflate_zstd(comp: bytes, raw_len: int, max_window_log: int) -> bytes:
    module = _zstd()
    if module is None:
        raise BackendError("zstd is not available; install opentine[zstd]")
    header, content, window, did, has_ck = _frame_header(comp)
    if _frame_length(comp, header, has_ck) != len(comp):
        raise BackendError("data after the frame")
    if content != raw_len:
        raise BackendError("frame size differs from the declared length")
    if window > max(1 << max_window_log, 1 << 10):
        raise BackendError("window too large")
    if did:
        raise BackendError("dictionary frames are not accepted")
    log_max = min(31, max(10, max_window_log))
    engine = module.ZstdDecompressor(
        options={module.DecompressionParameter.window_log_max: log_max}
    )
    try:
        out = engine.decompress(_MAGIC + comp, max_length=raw_len)
        if not engine.eof:
            out += engine.decompress(b"", max_length=1)
    except module.ZstdError as exc:
        raise BackendError(str(exc)) from None
    if not engine.eof or engine.unused_data:
        raise BackendError("zstd frame not exact")
    return out


def decompress(codec: int, comp: bytes, raw_len: int, max_window_log: int = 27) -> bytes:
    if codec == ZSTD:
        out = _inflate_zstd(comp, raw_len, max_window_log)
    elif codec == ZLIB:
        engine = zlib.decompressobj()
        try:
            out = engine.decompress(comp, raw_len + 1)
        except zlib.error as exc:
            raise BackendError(str(exc)) from None
        if not engine.eof or engine.unused_data or engine.unconsumed_tail:
            raise BackendError("zlib stream not exact")
    else:
        raise BackendError(f"unknown codec {codec!r}")
    if len(out) != raw_len:
        raise BackendError("length differs from the declared length")
    return out
