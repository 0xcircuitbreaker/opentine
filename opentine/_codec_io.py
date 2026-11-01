"""Writing portable ``.tine`` artifacts compressed, and reading either form."""

from __future__ import annotations

import os
import stat
import tempfile
from pathlib import Path

from opentine import _codec
from opentine._canon import _replace, atomic_write_text

#: Autosave drafts are rewritten often: a fast level costs little in size.
DRAFT_LEVEL = 1


def write_artifact(
    path: str | Path, text: str, *, fsync: bool = False, draft: bool = False
) -> Path:
    """Write a serialized artifact, compressed unless that is turned off.

    ``OPENTINE_COMPRESS=0`` writes the plain JSON every opentine release reads;
    so does a body too small to gain from compression.
    """
    codec = _codec.wanted()
    if codec is not None:
        data = _codec.wrap(
            text.encode("utf-8", errors="surrogatepass"),
            codec,
            level=DRAFT_LEVEL if draft and codec == "zstd" else None,
        )
        if data is not None:
            return atomic_write_bytes(path, data, fsync=fsync)
    return atomic_write_text(path, text, fsync=fsync)


def atomic_write_bytes(path: str | Path, data: bytes, *, fsync: bool = False) -> Path:
    """``atomic_write_text`` for bytes: temp file in place, then ``os.replace``."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        dir=str(target.parent), prefix=f".{target.name}.", suffix=".tmp"
    )
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            if fsync:
                handle.flush()
                os.fsync(handle.fileno())
        try:
            os.chmod(tmp, stat.S_IMODE(os.stat(target).st_mode))
        except FileNotFoundError:
            pass
        _replace(tmp, target)
    finally:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass
    return target


def recompress(path: str | Path, *, decompress: bool = False) -> tuple[int, int]:
    """Rewrite one artifact compressed (or plain); return (bytes before, after).

    The JSON inside is not reparsed or reserialized, so its digest and any
    signature are untouched: only the stored form changes.
    """
    from opentine._artifact_io import MAX_TINE_ARTIFACT_BYTES, read_artifact_bytes

    target = Path(path)
    before = target.stat().st_size
    raw = read_artifact_bytes(target)
    if decompress:
        with target.open("rb") as handle:
            head = handle.read(len(_codec.MAGIC))
        if not _codec.is_wrapped(head):
            return before, before
        atomic_write_bytes(target, raw)
        return before, len(raw)
    if len(raw) > MAX_TINE_ARTIFACT_BYTES:
        raise ValueError(".tine artifact exceeds the 256 MiB size limit")
    codec = _codec.wanted() or _codec.default_codec()
    data = _codec.wrap(raw, codec)
    if data is None or len(data) >= before:
        return before, before
    atomic_write_bytes(target, data)
    return before, len(data)


def standard_frame(data: bytes, fmt: str) -> bytes:
    """*data* as a plain ``.gz`` or ``.zst`` file other tools open directly."""
    if fmt == "gzip":
        import gzip

        return gzip.compress(data, mtime=0)
    if fmt == "zstd":
        return _codec.compress_frame(data, "zstd", 19)
    raise ValueError(f"unknown compression format {fmt!r}")
