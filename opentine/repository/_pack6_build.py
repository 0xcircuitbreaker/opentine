"""Writing ``TINEPACK6``: HEC where it pays, plain zstd where it does not (0.81).

HEC codes canonical JSON objects far smaller than zstd alone, but binary blob
bodies come out larger (measured 0.90x) and sealed (``TINEAES*``) bodies are
opaque by design. The writer tries, on the same objects:

* ``hec`` -- every object in the HEC1 body;
* ``split`` -- binary and sealed blobs in the plain section, the rest HEC
  (only when there are any);
* ``plain`` -- every object in the plain section (an empty HEC1 body): the
  ``TINEPACK5`` zstd long-mode stream of the same bytes in the same order;

and keeps the smallest, so a v6 pack is never larger than the plain zstd form
of its objects by more than the v6 frame.
"""

from __future__ import annotations

from opentine import _hec
from opentine.repository._pack6 import V6, frame
from opentine.repository._pack_v3 import stored_forms

#: zstd level of the HEC streams (they are small once ids are elided).
HEC_LEVEL = 19
_SEALED = b"TINEAES"


def opaque(raw: bytes) -> bool:
    """A blob whose body HEC cannot see into: sealed, or not UTF-8 text."""
    if not raw.startswith(b'{"encoding":"raw"'):
        return False
    body = raw.split(b"\n", 1)[1] if b"\n" in raw else b""
    if body.startswith(_SEALED) or b"\0" in body:
        return True
    try:
        body.decode("utf-8")
    except UnicodeDecodeError:
        return True
    return False


def _hec_pack(rows: list[bytes], level: int) -> bytes:
    split = [_hec.opentine1.split(raw) for raw in rows]
    order = _hec.dependency_order(split, _hec.OPENTINE)
    return _hec.encode([split[i] for i in order], _hec.OPENTINE, level=level)


def candidates(
    objects: list[tuple[str, bytes]], shallow: list[str], *, level: int = HEC_LEVEL
) -> dict[str, bytes]:
    """Every candidate pack by name (``hec``, ``split``, ``plain``)."""
    rows = [raw for _, _, _, raw in stored_forms(sorted(objects), slim=False)]
    out = {"plain": frame(_hec_pack([], level), rows, shallow)}
    out["hec"] = frame(_hec_pack(rows, level), [], shallow)
    binary = [raw for raw in rows if opaque(raw)]
    if binary and len(binary) < len(rows):
        text = [raw for raw in rows if not opaque(raw)]
        out["split"] = frame(_hec_pack(text, level), binary, shallow)
    return out


def build(objects: list[tuple[str, bytes]], shallow: list[str], *, level: int = HEC_LEVEL) -> bytes:
    """The smallest v6 pack of *objects* (``(oid, raw)``) and *shallow* boundaries."""
    return min(candidates(objects, shallow, level=level).values(), key=len)


def from_v3(data: bytes) -> bytes:
    """The v6 form of a v3 pack: same objects, same boundaries."""
    from opentine.repository.pack import inspect_pack

    _, objects, shallow = inspect_pack(data)
    return build(objects, shallow)


__all__ = ["HEC_LEVEL", "V6", "build", "candidates", "from_v3", "opaque"]
