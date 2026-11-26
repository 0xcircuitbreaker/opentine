"""In-file provenance pointers for produced artifacts (0.84).

A pointer is a short string naming the run that produced an artifact, written
into the format's own standard metadata slot. It is never the authority: the
signed sidecar (:mod:`opentine._artifact_provenance`) is. The pointer lets a
reader find the run, and lets ``tine provenance verify`` notice that it was
stripped or repointed.

=========  ==========================================================================
format     slot
=========  ==========================================================================
PNG        a ``tEXt`` chunk (``iTXt`` is also read) with keyword ``opentine:provenance``
           whose text is the run id, inserted before ``IEND``
JPEG       a ``COM`` segment ``opentine:provenance <run id>`` right after ``SOI``
PDF        an incremental update whose new ``/Info`` dictionary holds
           ``/OpentineProvenance (<run id>)`` (classic ``trailer`` PDFs only)
other      none: the sidecar alone
=========  ==========================================================================

**The artifact digest** is the sha256 of the *canonical* bytes: the file with
every opentine pointer removed and, for PNG and JPEG, every C2PA manifest store
(``caBX`` chunks, ``APP11`` segments) removed too. For PDF the canonical bytes
are the file before the pointer update, which is recognised only when it matches
the exact form this module writes. Anything else stays in the canonical bytes,
so any other change to the file changes the digest. Embedding always starts from
the canonical bytes, so embedding twice replaces the old pointer.
"""

from __future__ import annotations

import hashlib
import re
import struct
import zlib

KEYWORD = b"opentine:provenance"
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
MAX_PARTS = 1 << 16
_RUN = re.compile(rb"run:sha256:[0-9a-f]{64}")
_PDF_MARK = b"\n%opentine-provenance-update\n"
_PDF_BLOCK = re.compile(
    rb"(\d+) 0 obj\n<< /OpentineProvenance \((run:sha256:[0-9a-f]{64})\) >>\nendobj\n"
    rb"xref\n\1 1\n(\d{10}) 00000 n \ntrailer\n<< /Size (\d+) /Root (\d+ \d+ R) /Info \1 0 R"
    rb" /Prev (\d+) >>\nstartxref\n(\d+)\n%%EOF\n"
)


class PointerUnsupported(ValueError):
    """The artifact's format has no slot this module writes (sidecar only)."""


def media(data: bytes) -> str:
    if data.startswith(PNG_MAGIC):
        return "png"
    if data.startswith(b"\xff\xd8"):
        return "jpeg"
    if data.startswith(b"%PDF-"):
        return "pdf"
    return "other"


def _png_chunks(data: bytes) -> list[tuple[bytes, bytes, bytes]]:
    """``[(type, payload, raw chunk bytes)]``; ``ValueError`` on a malformed file."""
    out, at = [], len(PNG_MAGIC)
    while at < len(data):
        if at + 12 > len(data) or len(out) >= MAX_PARTS:
            raise ValueError("malformed PNG: truncated chunk")
        (size,) = struct.unpack(">I", data[at : at + 4])
        kind, end = data[at + 4 : at + 8], at + 12 + size
        if end > len(data) or not kind.isalpha():
            raise ValueError("malformed PNG: chunk overruns the file")
        payload = data[at + 8 : at + 8 + size]
        if struct.unpack(">I", data[end - 4 : end])[0] != zlib.crc32(kind + payload):
            raise ValueError(f"malformed PNG: bad CRC on a {kind.decode('ascii')} chunk")
        out.append((kind, payload, data[at:end]))
        at = end
        if kind == b"IEND":
            break
    if not out or out[0][0] != b"IHDR" or out[-1][0] != b"IEND" or at != len(data):
        raise ValueError("malformed PNG: IHDR first and IEND last, nothing after it")
    return out


def _png_pointer(kind: bytes, payload: bytes) -> bytes | None:
    if kind not in (b"tEXt", b"iTXt") or not payload.startswith(KEYWORD + b"\x00"):
        return None
    text = payload[len(KEYWORD) + 1 :]
    if kind == b"iTXt":  # only the plain form: no compression, empty language and keyword
        return text[4:] if text.startswith(b"\x00" * 4) else None
    return text


def _jpeg_segments(data: bytes) -> tuple[list[tuple[int, bytes]], bytes]:
    """``([(marker, raw segment)], rest from SOS)``; ``ValueError`` on a malformed file."""
    out, at = [], 2
    while True:
        if at + 4 > len(data) or data[at] != 0xFF or len(out) >= MAX_PARTS:
            raise ValueError("malformed JPEG: expected a marker segment")
        marker = data[at + 1]
        if marker == 0xDA:
            return out, data[at:]
        (size,) = struct.unpack(">H", data[at + 2 : at + 4])
        if size < 2 or at + 2 + size > len(data):
            raise ValueError("malformed JPEG: segment overruns the file")
        out.append((marker, data[at : at + 2 + size]))
        at += 2 + size


def _jpeg_pointer(marker: int, raw: bytes) -> bytes | None:
    body = raw[4:]
    return body[len(KEYWORD) + 1 :] if marker == 0xFE and body.startswith(KEYWORD + b" ") else None


def split(data: bytes) -> tuple[bytes, list[str]]:
    """``(canonical bytes, [pointer texts found])``; pointer texts are decoded leniently."""
    kind, found = media(data), []
    if kind == "png":
        kept = [PNG_MAGIC]
        for ctype, payload, raw in _png_chunks(data):
            text = _png_pointer(ctype, payload)
            if text is not None:
                found.append(text)
            elif ctype != b"caBX":
                kept.append(raw)
        canonical = b"".join(kept)
    elif kind == "jpeg":
        segments, rest = _jpeg_segments(data)
        kept = [data[:2]]
        for marker, raw in segments:
            text = _jpeg_pointer(marker, raw)
            if text is not None:
                found.append(text)
            elif marker != 0xEB:
                kept.append(raw)
        canonical = b"".join(kept) + rest
    elif kind == "pdf":
        canonical = data
        at = data.rfind(_PDF_MARK)
        match = _PDF_BLOCK.fullmatch(data, at + len(_PDF_MARK)) if at >= 0 else None
        if match is not None:
            canonical, found = data[:at], [match.group(2)]
    else:
        canonical = data
    return canonical, [t.decode("utf-8", "replace") for t in found]


def stores(data: bytes) -> str | None:
    """``sha256:`` of the C2PA store bytes the canonical form drops, in file order.

    ``None`` when there are none. The sidecar signs this, so a store added,
    removed or swapped outside the artifact digest is still caught.
    """
    kind, raw = media(data), []
    if kind == "png":
        raw = [r for c, _, r in _png_chunks(data) if c == b"caBX"]
    elif kind == "jpeg":
        raw = [r for m, r in _jpeg_segments(data)[0] if m == 0xEB]
    return "sha256:" + hashlib.sha256(b"".join(raw)).hexdigest() if raw else None


def digest(data: bytes) -> str:
    """The artifact digest: ``sha256:`` of the canonical bytes."""
    return "sha256:" + hashlib.sha256(split(data)[0]).hexdigest()


def _png_chunk(kind: bytes, payload: bytes) -> bytes:
    return (
        struct.pack(">I", len(payload))
        + kind
        + payload
        + struct.pack(">I", zlib.crc32(kind + payload))
    )


def _pdf_update(data: bytes, run: str) -> bytes:
    tail = data[-2048:]
    prev = re.search(rb"startxref\s+(\d+)\s+%%EOF\s*$", tail)
    at = data.rfind(b"trailer")
    trailer = data[at : at + 4096] if at >= 0 else b""
    root = re.search(rb"/Root\s+(\d+ \d+ R)", trailer)
    size = re.search(rb"/Size\s+(\d+)", trailer)
    if prev is None or root is None or size is None:
        raise PointerUnsupported("this PDF has no classic trailer (cross-reference streams)")
    base = data + _PDF_MARK
    n = int(size.group(1))
    obj = f"{n} 0 obj\n<< /OpentineProvenance ({run}) >>\nendobj\n".encode("ascii")
    xref = len(base) + len(obj)
    tail_text = (f"xref\n{n} 1\n{len(base):010d} 00000 n \ntrailer\n<< /Size {n + 1} /Root "
                 f"{root.group(1).decode('ascii')} /Info {n} 0 R /Prev {prev.group(1).decode()} "
                 f">>\nstartxref\n{xref}\n%%EOF\n")  # fmt: skip
    return base + obj + tail_text.encode("ascii")


def embed(data: bytes, run: str) -> tuple[bytes, str]:
    """``(new bytes, slot name)`` with a pointer to *run*; :class:`PointerUnsupported`."""
    if not _RUN.fullmatch(run.encode("ascii", "replace")):
        raise ValueError("a run is named by its run:sha256:<64 lowercase hex> id")
    canonical, _ = split(data)
    kind = media(canonical)
    if kind == "png":
        chunks = _png_chunks(canonical)
        body = b"".join(raw for _, _, raw in chunks[:-1])
        pointer = _png_chunk(b"tEXt", KEYWORD + b"\x00" + run.encode("ascii"))
        return PNG_MAGIC + body + pointer + chunks[-1][2], "png-text"
    if kind == "jpeg":
        comment = KEYWORD + b" " + run.encode("ascii")
        segment = b"\xff\xfe" + struct.pack(">H", len(comment) + 2) + comment
        return canonical[:2] + segment + canonical[2:], "jpeg-comment"
    if kind == "pdf":
        return _pdf_update(canonical, run), "pdf-info"
    raise PointerUnsupported("this format has no pointer slot; the sidecar alone records it")


__all__ = ["KEYWORD", "PointerUnsupported", "digest", "embed", "media", "split", "stores"]
