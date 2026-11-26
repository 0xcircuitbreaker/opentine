"""0.84 review: bytes the artifact digest leaves out cannot hide unbound content.

1. A C2PA store (PNG ``caBX`` / JPEG ``APP11``) added after embedding is outside
   the canonical bytes, so the sidecar binds the stores' digest and verify
   catches an added or swapped store with or without the optional C2PA extra.
2. A PNG ``iTXt`` pointer is recognised only in the exact plain form; extra bytes
   in its language or translated-keyword fields stay in the digest.
"""

from __future__ import annotations

import struct

import pytest

from opentine import _artifact_trailer as trailer
from tests.key_roles_helpers import isolated_trust_config  # noqa: F401
from tests.provenance_fixture import _room, chunk, codes, embed, jpeg, png, verify  # noqa: F401

pytestmark = pytest.mark.filterwarnings("ignore::Warning")


def _with_png_chunk(data: bytes, raw: bytes) -> bytes:
    return data[:-12] + raw + data[-12:]


def test_an_added_png_c2pa_store_is_detected(capsys, room):
    path = room["tmp"] / "a.png"
    path.write_bytes(png())
    embed(capsys, room, path)
    path.write_bytes(_with_png_chunk(path.read_bytes(), chunk(b"caBX", b"hidden payload")))
    code, body = verify(capsys, room, path)
    assert code == 1 and "artifact.c2pa-invalid" in codes(body)


def test_an_added_jpeg_app11_segment_is_detected(capsys, room):
    path = room["tmp"] / "a.jpg"
    path.write_bytes(jpeg())
    embed(capsys, room, path)
    data = path.read_bytes()
    seg = b"\xff\xeb" + struct.pack(">H", 2 + 14) + b"hidden payload"
    path.write_bytes(data[:2] + seg + data[2:])
    code, body = verify(capsys, room, path)
    assert code == 1 and "artifact.c2pa-invalid" in codes(body)


def test_an_itxt_pointer_with_extra_fields_stays_in_the_digest(capsys, room):
    path = room["tmp"] / "a.png"
    path.write_bytes(png())
    embed(capsys, room, path)
    canonical = trailer.split(path.read_bytes())[0]
    smuggled = trailer.KEYWORD + b"\x00\x00\x00hidden\x00more\x00" + room["run"].encode()
    path.write_bytes(_with_png_chunk(canonical, chunk(b"iTXt", smuggled)))
    code, body = verify(capsys, room, path)
    assert code == 1 and "artifact.digest-mismatch" in codes(body)


def test_a_plain_itxt_pointer_is_still_read(room):
    plain = trailer.KEYWORD + b"\x00\x00\x00\x00\x00" + room["run"].encode()
    data = _with_png_chunk(png(), chunk(b"iTXt", plain))
    assert trailer.split(data) == (png(), [room["run"]])
